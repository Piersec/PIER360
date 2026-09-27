# Gateway de leitura Wazuh — PIER360 DEV

Serviço Node.js pequeno, somente leitura, para ficar na rede Docker privada do Wazuh. O Vercel chama apenas este serviço por HTTPS; ele não publica as portas do Manager (`55000`) ou do Indexer (`9200`). O gateway implementa leitura de **agentes, detalhe do ativo e vulnerabilidades atuais**. O mapping do índice States foi conferido no cluster DEV; a implantação e a conexão ainda precisam ser configuradas.

## Rotas liberadas

- `GET /healthz` — health check sem dados de ambiente.
- `GET /v1/connections/{connection_key}/agents/summary`
- `GET /v1/connections/{connection_key}/agents?limit=25&offset=0&search=`
- `GET /v1/connections/{connection_key}/agents/{agent_id}`
- `GET /v1/connections/{connection_key}/vulnerabilities/summary`
- `GET /v1/connections/{connection_key}/vulnerabilities?limit=25&offset=0&search=&severity=`

Todas as rotas de dados exigem `Authorization: Bearer <WAZUH_GATEWAY_SERVICE_TOKEN>`. O gateway autentica na Manager API com um usuário somente leitura, conserva o JWT em memória por no máximo 12 minutos, e autentica separadamente no Indexer com um usuário somente leitura. Manager e Indexer usam URLs, credenciais e referências de CA próprias; ambos rejeitam TLS inválido. O gateway consulta exclusivamente `wazuh-states-vulnerabilities-*`, traduz o resultado para o contrato do PIER360 e não aceita DSL, índice ou caminho Wazuh enviado pelo navegador. Não há endpoints de escrita nem CORS.

A rota summary agrega `vulnerability.severity` e exige contagem exata. `Critical`, `High`, `Medium` e `Low` são normalizados para os valores canônicos; `-`, campo ausente ou valor desconhecido contam como `unknown`. A rota de lista devolve somente agente, CVE, pacote/versão, severidade, CVSS base e data de detecção. A identidade `findingKey` combina `_index` e `_id` para evitar colisões entre índices do padrão.

A paginação usa `from/size` e respeita a janela máxima de 10.000 documentos do Indexer; o gateway rejeita offsets que ultrapassem esse limite em vez de devolver uma página parcial.

O agente interno `000` é excluído da lista e da contagem paginada de ativos, em linha com o resumo oficial do Manager. A resposta também distingue `registeredAt` (`dateAdd`), `lastKeepAlive` e `syscollectorScanAt` (`scan.time`).

## Configuração

Variáveis obrigatórias:

- `WAZUH_GATEWAY_SERVICE_TOKEN` ou `WAZUH_GATEWAY_SERVICE_TOKEN_FILE`: segredo aleatório compartilhado somente com o Vercel Preview.
- `WAZUH_CONNECTION_KEY`: chave opaca cadastrada na linha `wazuh_connections` do tenant (DEV: `piersec-dev`).
- `WAZUH_MANAGER_URL`: URL HTTPS alcançável pelo container; não inclua usuário, senha nem query.
- `WAZUH_MANAGER_USERNAME` / `WAZUH_MANAGER_PASSWORD` ou suas variantes `_FILE`: credenciais do usuário Manager read-only (`agent:read` e `syscollector:read`).
- `WAZUH_MANAGER_CA_FILE`: caminho do certificado CA confiável montado dentro do container quando o Manager usa certificado privado.
- `WAZUH_INDEXER_URL`: URL HTTPS do Indexer alcançável pela rede Docker, normalmente na porta `9200`.
- `WAZUH_INDEXER_USERNAME` / `WAZUH_INDEXER_PASSWORD` ou suas variantes `_FILE`: credenciais de uma identidade separada com leitura/search apenas nos índices necessários. Não reutilize o usuário do Manager.
- `WAZUH_INDEXER_CA_FILE`: caminho do certificado CA confiável montado dentro do container quando o Indexer usa certificado privado. O gateway nunca desliga a validação TLS.

Use arquivos montados como read-only no Docker/Portainer para as credenciais e tokens. Não coloque secrets no repositório, no `.env.example`, em imagem Docker, no navegador ou no Supabase. Restrinja acesso de administradores a esses arquivos e faça rotação se forem expostos. Se Manager e Indexer forem assinados pela mesma CA, o mesmo arquivo PEM pode ser montado nos dois caminhos de CA.

## Executar para desenvolvimento

```powershell
docker build -t pier360-wazuh-gateway:dev .
```

No container, injete as variáveis de ambiente e monte os três arquivos de segredo e o CA como somente leitura. Evite mapear a porta `8787` para `0.0.0.0`; prefira rede interna Docker. O conector `cloudflared`, se usado, deve compartilhar uma rede privada com o gateway e rotear o hostname HTTPS do gateway para `http://wazuh-gateway:8787`. Não crie hostname do túnel para as portas 55000 ou 9200.

### Portainer

`compose.portainer.example.yml` é um modelo de Stack para importar junto com esta pasta do repositório. Antes de implantar, preencha os valores não secretos em **Environment variables** do Stack: `WAZUH_MANAGER_URL`, `WAZUH_INDEXER_URL`, `WAZUH_MANAGER_DOCKER_NETWORK`, `CLOUDFLARED_DOCKER_NETWORK` e os caminhos absolutos no host para os arquivos de segredo e CA. Manager e Indexer precisam estar acessíveis pela rede Docker ligada ao gateway; o conector `cloudflared` precisa compartilhar a rede indicada. Este modelo não publica `8787` na interface do host.

Crie cinco arquivos de segredo no host da VM, fora da pasta do repositório: usuário e senha do Manager, usuário e senha do Indexer e token de serviço. Crie também os arquivos PEM da CA que assina o TLS do Manager e do Indexer; podem ser o mesmo arquivo se ambos usarem a mesma CA. Conceda leitura ao UID/GID `1000:1000` do container (`node`). Se ainda não existe conector `cloudflared` no Docker dessa VM, interrompa antes do deploy e escolha como o túnel existente alcançará a rede Docker; não abra uma porta pública no roteador/firewall para contornar essa ligação.

Ao configurar a rota do túnel, use o nome DNS Docker `wazuh-gateway` como origin se o conector compartilha a rede indicada. O hostname público precisa usar HTTPS, mas a origem no Docker é `http://wazuh-gateway:8787`; o tráfego Vercel→Cloudflare continua em HTTPS e os endpoints Wazuh permanecem somente na rede privada.

Para gerar o segredo de serviço em uma máquina com OpenSSL:

```sh
openssl rand -hex 32
```

Salve-o em um arquivo de segredo do gateway e cadastre exatamente o mesmo valor como `WAZUH_GATEWAY_SERVICE_TOKEN` no **Vercel Preview**. Em seguida, configure `WAZUH_GATEWAY_URL` no Preview com o hostname HTTPS do túnel. Não configure essas duas variáveis em Production nesta etapa.

## Antes de habilitar

1. Confirmar o nome real da rede Docker e o DNS interno do container Manager e do `cloudflared` no Portainer.
2. Montar a CA correta do Manager (ou usar certificado emitido por CA confiável com SAN correspondente a `WAZUH_MANAGER_URL`).
3. Iniciar o gateway e confirmar `/healthz`.
4. Com curl, confirmar as cinco rotas usando um token de serviço e comparar agentes/detalhe com a Manager API e summary/lista com a consulta States já validada.
5. Configurar a rota do Cloudflare Tunnel para o gateway privado; nenhum bind de porta pública.
6. Configurar URL e token no ambiente Vercel Preview, cadastrar/ativar a conexão `piersec-dev` no tenant DEV e conferir Ativos no Preview.
7. Validar `registeredAt`, `lastKeepAlive` e `syscollectorScanAt` separadamente. A data do screenshot do Wazuh é a data de registro; o scan vem do inventário de pacotes.

Não prossiga para Production até passar os testes de integração, revisar os logs sem segredos e concluir o gate de segurança/UAT.
