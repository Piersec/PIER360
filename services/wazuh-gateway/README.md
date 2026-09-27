# Gateway de leitura Wazuh — PIER360 DEV

Serviço Node.js pequeno, somente leitura, para ficar na mesma rede Docker do Wazuh Manager. O Vercel chama apenas este serviço por HTTPS; ele não publica as portas do Manager (`55000`) ou do Indexer (`9200`). Nesta etapa, o gateway implementa **agentes e detalhe do ativo**. O Indexer permanece desligado até validarmos os mappings reais do índice States.

## Rotas liberadas

- `GET /healthz` — health check sem dados de ambiente.
- `GET /v1/connections/{connection_key}/agents/summary`
- `GET /v1/connections/{connection_key}/agents?limit=25&offset=0&search=`
- `GET /v1/connections/{connection_key}/agents/{agent_id}`

Todas as rotas de dados exigem `Authorization: Bearer <WAZUH_GATEWAY_SERVICE_TOKEN>`. O gateway autentica na Manager API com o usuário read-only existente, conserva o JWT em memória por no máximo 12 minutos, rejeita TLS inválido e só emite os campos documentados no contrato. Não há rota genérica de proxy, endpoints de escrita, CORS ou DSL do Indexer.

O agente interno `000` é excluído da lista e da contagem paginada de ativos, em linha com o resumo oficial do Manager. A resposta também distingue `registeredAt` (`dateAdd`), `lastKeepAlive` e `syscollectorScanAt` (`scan.time`).

## Configuração

Variáveis obrigatórias:

- `WAZUH_GATEWAY_SERVICE_TOKEN` ou `WAZUH_GATEWAY_SERVICE_TOKEN_FILE`: segredo aleatório compartilhado somente com o Vercel Preview.
- `WAZUH_CONNECTION_KEY`: chave opaca cadastrada na linha `wazuh_connections` do tenant (DEV: `piersec-dev`).
- `WAZUH_MANAGER_URL`: URL HTTPS alcançável pelo container; não inclua usuário, senha nem query.
- `WAZUH_MANAGER_USERNAME` / `WAZUH_MANAGER_PASSWORD` ou suas variantes `_FILE`: credenciais do usuário Manager read-only (`agent:read` e `syscollector:read`).
- `WAZUH_MANAGER_CA_FILE`: caminho do certificado CA confiável montado dentro do container quando o Manager usa certificado privado. O gateway não aceita desligar a validação TLS.

Use arquivos montados como read-only no Docker/Portainer para as credenciais. Não coloque secrets no repositório, no `.env.example`, em imagem Docker, no navegador ou no Supabase. Restrinja acesso de administradores a esses arquivos e faça rotação se forem expostos.

## Executar para desenvolvimento

```powershell
docker build -t pier360-wazuh-gateway:dev .
```

No container, injete as variáveis de ambiente e monte os três arquivos de segredo e o CA como somente leitura. Evite mapear a porta `8787` para `0.0.0.0`; prefira rede interna Docker. O conector `cloudflared`, se usado, deve compartilhar uma rede privada com o gateway e rotear o hostname HTTPS do gateway para `http://wazuh-gateway:8787`. Não crie hostname do túnel para as portas 55000 ou 9200.

### Portainer

`compose.portainer.example.yml` é um modelo de Stack para importar junto com esta pasta do repositório. Antes de implantar, preencha os valores não secretos em **Environment variables** do Stack: `WAZUH_MANAGER_URL`, `WAZUH_MANAGER_DOCKER_NETWORK`, `CLOUDFLARED_DOCKER_NETWORK` e os quatro caminhos absolutos dos arquivos no host terminados em `_FILE`. O Manager e o conector `cloudflared` precisam estar conectados às redes informadas. Este modelo não publica `8787` na interface do host.

Crie os arquivos de segredo no host da VM fora da pasta do repositório e conceda leitura ao UID/GID `1000:1000` do container (`node`). O certificado deve ser a CA/certificado PEM confiável que assina o TLS do Manager. Se ainda não existe conector `cloudflared` no Docker dessa VM, interrompa antes do deploy e escolha como o túnel existente alcançará a rede Docker; não abra uma porta pública no roteador/firewall para contornar essa ligação.

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
4. Com curl, confirmar as três rotas usando um token de serviço, e comparar resumo/agentes/detalhe com a Manager API já testada.
5. Configurar a rota do Cloudflare Tunnel para o gateway privado; nenhum bind de porta pública.
6. Configurar URL e token no ambiente Vercel Preview, cadastrar/ativar a conexão `piersec-dev` no tenant DEV e conferir Ativos no Preview.
7. Validar `registeredAt`, `lastKeepAlive` e `syscollectorScanAt` separadamente. A data do screenshot do Wazuh é a data de registro; o scan vem do inventário de pacotes.

Não prossiga para Production até passar os testes de integração, revisar os logs sem segredos e concluir o gate de segurança/UAT.
