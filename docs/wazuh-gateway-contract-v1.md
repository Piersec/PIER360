# Contrato do gateway Wazuh de leitura — PIER360 DEV

Este contrato separa o BFF hospedado no Vercel das APIs Manager/Indexer que permanecem na rede controlada do Wazuh. Na etapa atual, implementamos e autenticamos apenas as leituras de agentes. O serviço/gateway dentro da rede Wazuh e a conexão real ainda precisam ser provisionados.

## Limites de segurança

- O browser só acessa páginas do PIER360. Nunca recebe credenciais Wazuh e nunca chama as portas 55000 ou 9200.
- O BFF exige sessão Supabase AAL2 e grant `assets` no tenant antes de ler a conexão autorizada.
- O `connection_key` é lido da linha `wazuh_connections` do tenant validado; não é aceito em query/body do browser.
- O gateway exige um token de serviço recebido pelo BFF via `WAZUH_GATEWAY_SERVICE_TOKEN`. Esse segredo e `WAZUH_GATEWAY_URL` existem apenas no runtime server-side do Vercel.
- Manager API e Indexer API usam usuários separados, somente leitura, TLS validado, restrição de rede e privilégios mínimos. Não desabilitar validação TLS.
- O gateway expõe exclusivamente os GET abaixo. Não aceitar URLs, índices, DSL, caminhos Manager, ações remotas ou consultas arbitrárias fornecidos pelo chamador.
- Tempo limite da chamada BFF→gateway: 8 segundos. Redirecionamentos HTTP são recusados. Falhas, autenticação recusada, rate limit e resposta parcial nunca viram contagem zero.

## Operações Manager — fase de agentes

Todas as respostas são JSON. As rotas começam em `/v1/connections/{connection_key}`. `connection_key` é um identificador opaco da linha autorizada em `public.wazuh_connections`, não um secret. O gateway deve recusar chaves desconhecidas.

### `GET /v1/connections/{connection_key}/agents/summary`

Ler Wazuh Manager `GET /agents/summary`. A distribuição oficial vem de `data.status` com os estados que existirem na versão do cluster. O gateway normaliza para:

```json
{
  "source": "wazuh-manager",
  "completeness": "complete",
  "queriedAt": "2026-09-26T18:00:00Z",
  "status": {
    "active": 12,
    "disconnected": 2,
    "pending": 1,
    "neverConnected": 3,
    "other": 0,
    "total": 18
  }
}
```

`other` agrega apenas estados de origem não mapeados; `total` é derivado de todos os estados de origem retornados. `pending` e `never_connected` permanecem distinguíveis na origem e são somados no cartão Pendente. O BFF valida que os cinco valores fecham o total. Só responder `complete` quando a leitura estiver completa e a soma fechar.

### `GET /v1/connections/{connection_key}/agents?limit=25&offset=0&search=texto`

O gateway chama somente `GET /agents` da Manager API, com paginação e seleção restrita a `id,name,ip,status,lastKeepAlive,os`. `search` filtra nome, IP ou ID, com limite de tamanho no gateway. Resposta canônica:

```json
{
  "source": "wazuh-manager",
  "completeness": "complete",
  "queriedAt": "2026-09-26T18:00:00Z",
  "items": [{
    "id": "001",
    "name": "host-exemplo",
    "ip": "192.0.2.10",
    "rawStatus": "active",
    "lastKeepAlive": "2026-09-26T17:58:00Z",
    "osName": "Ubuntu",
    "osVersion": "24.04"
  }],
  "page": { "limit": 25, "offset": 0, "total": 1 }
}
```

A lista não dispara uma chamada Syscollector por linha. O status original permanece em `rawStatus`; o PIER360 traduz somente para exibição.

### `GET /v1/connections/{connection_key}/agents/{agent_id}`

O gateway valida `agent_id` e consulta o agente por `GET /agents?agents_list=...&select=id,name,ip,status,lastKeepAlive,os`. Somente ao abrir a ficha, consulta `GET /syscollector/{agent_id}/packages` com paginação/seleção mínima suportada pela versão instalada para extrair `scan.time` (ou alias validado, como `scan_time`). Não devolver a lista completa de pacotes.

```json
{
  "source": "wazuh-manager",
  "completeness": "complete",
  "queriedAt": "2026-09-26T18:00:00Z",
  "agent": {
    "id": "001",
    "name": "host-exemplo",
    "ip": "192.0.2.10",
    "rawStatus": "active",
    "lastKeepAlive": "2026-09-26T17:58:00Z",
    "osName": "Ubuntu",
    "osVersion": "24.04",
    "syscollectorScanAt": "2026-09-26T17:55:00Z"
  }
}
```

`lastKeepAlive` é último contato; `syscollectorScanAt` é o scan do inventário de software. São conceitos diferentes. Se o gateway não conseguir confirmar a segunda consulta, deve sinalizar erro/partial; não retornar uma ficha `complete` inventando `null` como se a consulta tivesse sido feita.

## Operações Indexer — etapa seguinte

O padrão de rota Indexer fica fora desta entrega de agentes. A próxima subfase definirá uma operação tipada para o índice `wazuh-states-vulnerabilities-*`, paginação/aggregations e semântica de resposta parcial com base no contrato real do cluster. O gateway jamais aceitará nome de índice, DSL ou endpoint arbitrário do browser.

## Configuração pendente no DEV

- Confirmar versão Wazuh e contrato Manager/Indexer instalado.
- Provisionar o gateway HTTPS na rede controlada e provar a rota de saída do Vercel Preview até ele, sem expor Manager/Indexer publicamente.
- Criar identidades distintas read-only para Manager e Indexer e instalar certificados confiáveis.
- Definir no Vercel Preview `WAZUH_GATEWAY_URL` e `WAZUH_GATEWAY_SERVICE_TOKEN` como variáveis server-side.
- Cadastrar uma conexão ativa para o tenant Piersec na tabela existente `wazuh_connections`, usando somente a chave opaca e referência a secret; não armazenar senha/token Wazuh nessa tabela.
- Validar manualmente os exemplos de retorno e reconciliação com um Manager não produtivo. A conexão DEV atual está ausente, portanto as telas informam isso e não exibem zeros fictícios.

