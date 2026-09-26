# Contratos Wazuh usados pelo PUS

Referência enxuta para implementação; não substitui a documentação da versão instalada. Consultado em 25/09/2026; documentação corrente publicada para Wazuh 4.14.7.

## Agentes

- Manager API: [referência da API](https://documentation.wazuh.com/current/user-manual/api/reference.html) e [listar agentes](https://documentation.wazuh.com/current/user-manual/agent/agent-management/listing/listing.html).
- `GET /agents/summary` retorna contagens em `data.status` (`active`, `disconnected`, `pending`, `never_connected`); derive o total da soma dos estados retornados. `GET /agents/summary/status` é outro endpoint, voltado aos estados de conexão e sincronização. Para um agente, o PDF fornecido exemplifica `GET /agents?agents_list={agent_id}&select=id,name,ip,status,lastKeepAlive,os`; valide filtros e campos com a versão instalada. A API oferece `limit`, `offset` e `select`; respostas de coleção são limitadas por padrão e devem ser paginadas.
- Os estados da API incluem `active`, `pending`, `never_connected` e `disconnected`. A tela da V1 tem três grupos; agrupe `pending` e `never_connected` em Pendente e preserve o valor de origem para auditoria/detalhe.
- `lastKeepAlive` é a base para “último contato”. Wazuh também documenta dados estatísticos por agente em `/agents/{agent_id}/stats/agent`, incluindo `last_keepalive` e `last_ack`.
- Para inventário do ativo, o Manager API expõe `GET /syscollector/{agent_id}/packages`. A documentação fornecida menciona `scan_time`; os exemplos atuais da API mostram `scan: { id, time }` em cada registro. Normalizar ambos somente após validar contrato/versão; o timestamp é o scan do Syscollector (inventário de software), não o último contato nem necessariamente o scan de vulnerabilidades. A coleção usa paginação e o campo de scan deve ser escolhido sem baixar pacotes completos se o contrato instalado permitir seleção/ordenação segura.
- O status histórico `wazuh-monitoring-*` é normalmente indexado em intervalos de 15 minutos. Se for exibida tendência histórica, informe sua granularidade; para estado atual, use a API do Manager ou valide o atraso do índice.
- Documentação: [índices Wazuh](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html), [conexão de agente](https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html).

## Vulnerabilidades

- A detecção correlaciona o inventário de software do Syscollector com o catálogo de inteligência de vulnerabilidades do Wazuh. A unidade apresentada pela integração é um registro agente + CVE + pacote/versão (validar identidade exata com os dados do cluster).
- A fonte corrente de leitura é o índice `wazuh-states-vulnerabilities-*`, consultado pela Indexer API via `_search` em cada requisição autorizada de dashboard/lista/detalhe. A documentação de exemplo expõe `agent.id`, `agent.name`, `host.os`, `package.name`, `package.version` e `vulnerability.id`, `vulnerability.severity`, `vulnerability.score`, `vulnerability.detected_at` e referências.
- “Em tempo real” neste produto significa consultar o estado atualmente indexado no momento da requisição; a latência de atualização ainda depende da coleta, do processamento e da indexação do Wazuh. Não persistir snapshot de vulnerabilidades no Supabase como fonte padrão para a UI. Workflows do PUS são persistidos separadamente e associados por identidade estável do finding/documento.
- Os antigos endpoints da Server API `/vulnerability/{agent_id}`, `/last_scan`, `/summary/{field}` e `PUT /vulnerability` foram removidos no Wazuh 4.8 após depreciação. Use Indexer API para buscar o inventário atual.
- O estado do inventário de vulnerabilidades é diferente do histórico de eventos/alertas (`wazuh-alerts-*`). Não leia alerta histórico como se fosse o conjunto de achados abertos atual.
- `vulnerability.detected_at` é a detecção do registro. Não prova por si só a hora do último scan completo do agente. Exponha também o horário e resultado da consulta Indexer, com semânticas corretas. Em falha, timeout ou resposta parcial, não apresentar contagens zero nem sinalizar resolução.
- O Wazuh pode produzir eventos quando vulnerabilidades são detectadas ou corrigidas; confirme comportamento, versão e completude antes de marcar um finding local como resolvido quando ele deixar de aparecer numa consulta.
- Documentação: [como funciona a detecção](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html), [consulta de vulnerabilidades na Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html), [índices globais](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html), [remoção dos endpoints legados no 4.8](https://documentation.wazuh.com/current/release-notes/release-4-8-0.html).

## Enriquecimento por CVE (V1)

- Consultar EPSS e KEV sem alterar nem substituir o finding Wazuh. A chave é `cve_id`; uma entrada pode enriquecer vários agentes/pacotes.
- EPSS publica score/percentile diariamente. Preferir consumir o CSV completo diário em lote, filtrar/guardar as CVEs encontradas na consulta atual Wazuh e registrar data efetiva do score. A API FIRST serve a lookups de uma CVE ou lotes pequenos; não criar uma chamada por finding.
- Atualizar CISA KEV pelo catálogo oficial JSON a cada 6 horas. Guardar os atributos disponíveis (incluindo `dateAdded`, prazo/ação e flag de ransomware quando presente), `fetched_at` e o resultado da última atualização concluída.
- Executar a agenda fora do Vercel Cron Hobby. Upsert idempotente; no erro manter o último valor válido com freshness antiga e reportar falha. Ausência no EPSS significa não disponível; KEV pode ser tratado como não listado somente após uma leitura válida e recente do catálogo.
- Dashboard/lista/detalhe juntam os dados armazenados ao resultado Indexer em lote no backend. Para cards/filtros por EPSS/KEV, agregar os findings atuais no Indexer por CVE e fazer o cruzamento no servidor.
- Fontes: [FIRST EPSS — dados, API e CSV](https://www.first.org/epss/data), [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Autenticação e operação

- A Server API usa JWT; a documentação atual informa duração padrão de 900 segundos. Obtenha e renove tokens no serviço de integração, sem persistir senha/token em browser ou logs.
- A Indexer API possui autenticação e controles próprios. Use usuário indexer limitado a leitura dos padrões exigidos. Mantenha Manager API e Indexer fora da exposição pública.
- As APIs aceitam paginação e filtros. Use seleção explícita de campos, paginação, timeouts, limites de concorrência e tratamento de 401/403/429/5xx; não consulte documentos sem limites para cada carregamento da página.
- Prefira conector dentro da rede Wazuh com conexões de saída autenticadas para o PUS, evitando expor portas administrativas. Se for adotado túnel privado, mantenha autenticação do serviço e regra de rede restritiva.

## Esboço de dados canônicos e overlay operacional

```text
agent (resposta transitória da Manager API):
  source_connection_id, source_agent_id, name, ip, raw_status, ui_status,
  os_name, os_version, last_keep_alive_at, syscollector_scan_at, queried_at

finding (resposta transitória da Indexer API):
  source_connection_id, source_document_id, source_agent_id, cve_id,
  package_name, package_version, severity, cvss_score, detected_at,
  source_state, references, queried_at

vulnerability_enrichment (PUS persistido; público/global por CVE):
  cve_id, epss_score, epss_percentile, epss_as_of,
  kev_listed, kev_date_added, kev_due_date, kev_required_action,
  kev_ransomware_use, source_fetched_at, source_status

work_item (PUS persistido):
  tenant_id, source_connection_id, finding_key, workflow_status, assignee_id, due_at,
  comment_count, accepted_risk_reason, updated_by, updated_at

source_query_run (metadados operacionais, sem cópia do finding):
  source_connection_id, data_domain, started_at, finished_at,
  result, records_read, duration_ms, error_code
```

Guarde a identificação da origem e timestamps de consulta. Vulnerabilidades são lidas do Indexer; persista somente overlay operacional, auditoria e métricas de execução. Inclua payload bruto somente se houver requisito de troubleshooting, retenção e acesso definido.

