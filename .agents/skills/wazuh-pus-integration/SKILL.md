---
name: wazuh-pus-integration
description: "Projetar e revisar integrações somente leitura entre Wazuh e uma plataforma PUS: contratos de agentes, inventário de vulnerabilidades, sincronização e isolamento multi-tenant."
---

# Integração Wazuh para o PUS

Use esta skill ao implementar ou revisar a integração do Wazuh com o PUS PIER360. As orientações foram preparadas para leitura de dados e gestão de vulnerabilidades no PUS; não autorizam mudanças no Wazuh.

## Contrato de dados

- Identifique a versão do Wazuh de cada conexão e valide o contrato contra a documentação dessa versão antes de desenvolver o conector.
- Consulte a Wazuh Server API para agentes e inventário do Syscollector e a Wazuh Indexer API para o estado atual de vulnerabilidades. São APIs distintas, com credenciais e permissões próprias.
- Para totais/distribuição de agentes, use `GET /agents/summary` e leia `data.status`; `GET /agents/summary/status` retorna o resumo de status de conexão/sincronização, não a distribuição usada nos cartões. Para ficha/lista, consulte `GET /agents?agents_list={agent_id}&select=id,name,ip,status,lastKeepAlive,os` (ou o filtro/rota equivalente validado na versão instalada). Trate paginação por `limit`/`offset` nas coleções; a resposta padrão é limitada.
- Para horário do último scan do inventário de software, consulte `GET /syscollector/{agent_id}/packages` conforme a documentação fornecida. As respostas atuais documentadas incluem `scan.time`; versões/contratos anteriores podem chamar o campo `scan_time`. Validar o formato, fuso e custo de paginação na versão instalada. Isso representa scan Syscollector, não scan de vulnerabilidades.
- Preserve o status original. Para a interface, mapeie `active` para Ativo, `disconnected` para Desconectado e `pending`/`never_connected` para Pendente, com o subtipo disponível no detalhe.
- Para leitura atual de vulnerabilidades, consulte `wazuh-states-vulnerabilities-*` na Indexer API no servidor/backend em cada requisição autorizada. Não use uma projeção periódica como fonte de leitura padrão nem baseie uma integração nova nos antigos endpoints `/vulnerability`; foram removidos/depreciados a partir do Wazuh 4.8. Confirme o esquema real do cluster antes de definir mapeamentos.
- Para EPSS e CISA KEV, mantenha um enrichment público por CVE separado dos findings ao vivo. Atualize EPSS em lote por CSV uma vez ao dia e KEV pelo catálogo oficial em rotina agendada; associe no backend, registre fonte/data e não faça chamada externa por linha/finding. Em falha, preserve o último enrichment marcando-o desatualizado; ausência de EPSS nunca é score 0 e falha de atualização KEV nunca é “não listado”.
- Use uma identidade estável da origem e, quando necessário, uma chave composta por conexão, agente, CVE e identidade do pacote. Mantenha o tratamento do PUS separado dos dados de detecção do Wazuh.
- Distinga `lastKeepAlive` (último contato), `scan.time`/`scan_time` (scan do inventário Syscollector), `vulnerability.detected_at` (detecção do registro) e horário da consulta ao Indexer. Não os trate como equivalentes.
- Não converta falha, dado ausente, timeout ou resposta Indexer parcial em zero ou em “resolvida”. Informe falha/horário da consulta e só altere estado de origem após regra de resolução validada; o workflow do PUS permanece separado.

## Segurança e tenancy

- Nunca chame Manager API ou Indexer API do navegador. Mantenha credenciais no conector ou serviço server-side, valide TLS e use identidades de privilégio mínimo limitadas a leitura.
- Restrinja endpoints e índices consultáveis; não aceite do browser URLs, nomes de índice, DSL livre ou credenciais Wazuh.
- Trate Wazuh como fonte de inventário/detecção e o banco do PUS como fonte do vínculo usuário-tenant, permissões de módulos e estado operacional do tratamento (responsável, comentários e aceite de risco).
- Derive `tenant_id` de uma conexão autorizada no backend, nunca do payload do cliente. Aplique autorização no servidor e RLS em toda tabela multi-tenant.
- Registre metadados mínimos das consultas em tempo real e reporte latência/erro da origem. Não substitua falha por zeros nem apresente cópia antiga como estado atual sem identificá-la.

Leia [references/wazuh-data-contracts.md](references/wazuh-data-contracts.md) para endpoints, status, índices e ligações oficiais relevantes. Leia apenas as seções necessárias para a tarefa.

