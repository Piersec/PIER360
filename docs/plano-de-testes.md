# Plano de testes do PUS PIER360 V1.0

Este é o plano a executar durante o desenvolvimento e antes do go-live. O protótipo de interface usa dados DEMO; os conectores Wazuh, a persistência Supabase e os controles de produção ainda precisam ser implementados e validados.

## Ambientes e dados

- Desenvolver com dados sintéticos e stubs Wazuh.
- Manter ambiente de integração contra Wazuh não produtivo, com tenant/dados sanitizados.
- Usar staging com versões iguais/compatíveis às versões de produção; nunca rodar carga ou scripts de teste destrutivo contra o cluster produtivo.
- Registrar versão do Wazuh, configuração de status/scan, payload real de `scan.time`/`scan_time` e amostra de schema aprovada.

## Camadas de teste

| Camada | Cobertura | Exemplos de saída esperada |
|---|---|---|
| Unitário | Mapeamento e agregação | `active`, `disconnected`, `pending`, `never_connected`; contagens do resumo; `lastKeepAlive` separado de `scan.time`/`scan_time`; vulnerabilidade sem CVSS/IP/timestamp; classificação binária por tenant/conexão/agent; contagem de ativos críticos e soma de vulnerabilidades associadas sem mudar score de risco; precedência KEV, cortes EPSS inclusivos, EPSS ausente pendente e ordenação compartilhada; timezone UTC. |
| Contrato do conector | Server API e Indexer API | JWT expirado, 401/403/429/5xx, timeout, limite/paginação, campos ausentes e variações de versão; leitura somente, índices/campos permitidos e consulta ao estado corrente. |
| Integração de leitura | Gateway + Manager/Indexer + Postgres | Chamadas ao vivo no carregamento, Indexer filter/aggregation/pagination, identidade de documento, overlay work item em lote, 401/timeout/resposta parcial e nenhuma atualização incorreta de workflow. |
| Enriquecimento agendado | Worker + FIRST EPSS + CISA KEV + tabela de enrichment | EPSS CSV diário, KEV JSON a cada 6h, normalização/junção por CVE, upsert idempotente, replay, CVE sem score, atualização incompleta, retry/backoff e freshness por fonte. |
| Banco/autorização | Auth, RLS, membership, capabilities | Tenant A não lê/edita tenant B; usuário sem módulo não consulta API/tabelas; somente usuários autorizados alteram classificação crítica e corte EPSS; alterações ficam auditadas e não vazam entre tenants; super admin pode administrar grants; usuário não eleva o próprio acesso; secret key só no servidor. |
| Segurança de login | CAPTCHA/MFA/sessão | Turnstile válido, ausente, expirado e replay; MFA TOTP habilitado, challenge, AAL1 bloqueado e AAL2 aceito; convite expirado e conta desativada; rate limit e mensagens neutras. |
| UI/e2e | Fluxos de produto | Dashboard -> filtro -> finding -> voltar; rótulos descritivos e cartões removidos; fila sem rolagem horizontal; busca/filtros; ficha do agente; convite/admin; workflow, comentário e audit log; luz/escuro, teclado e viewports. |
| Desempenho/resiliência | Volume representativo | Paginação Manager/Indexer, agregações, resposta p95, limite de concorrência, Wazuh indisponível, estado “indisponível” em vez de zero e retomada sem leitura duplicada/elevação de carga. |
| UAT | Operação real | Super admin administra usuários e módulos; analista vê e trata vulnerabilidades do próprio tenant; operador reconcilia agentes e aging com Wazuh. |

## Casos de aceite prioritários

1. Reconciliar total e distribuição usando `GET /agents/summary/status`; conferir `pending` e `never_connected` no grupo Pendente e detalhamento original.
2. Confirmar que IP/status/`lastKeepAlive` pertencem ao agente correto. Comparar timestamp de scan retornado por `/syscollector/{agent_id}/packages` com `scan.time` ou `scan_time` no payload real e garantir que o rótulo/fuso seja inequívoco.
3. Marcar e desmarcar um agente como crítico; confirmar persistência após recarga, isolamento por tenant/conexão, atualização da classificação na lista/ficha e tabela de ativos impactados, e score de risco inalterado.
4. Validar a regra: KEV sempre precede EPSS; itens sem KEV com EPSS igual ao corte entram na faixa destacada; abaixo do corte permanecem na lista; sem EPSS ficam pendentes, sem converter ausência em zero. Confirmar a mesma ordem no dashboard, lista, detalhe e filtro de ativos.
5. Alterar o corte para um tenant e confirmar mudança nos totais/ordenação desse tenant; outro tenant mantém o próprio valor. Usuário sem capability não altera; auditoria registra antes/depois.
6. Garantir que a chave de vulnerabilidade não colapse CVE repetida em pacotes/hosts diferentes.
7. Comparar agregações do dashboard, filtros, lista e detalhe consultados do Indexer: severidade, agente e contagem de ativos afetados devem concordar.
8. Alterar/atualizar um registro no ambiente Wazuh de teste e confirmar que a próxima leitura autorizada consulta o estado indexado atual; medir horário/camada de atualização e confirmar ausência de snapshot periódico como fonte UI.
9. Induzir timeout, falha de shards e resposta parcial do Indexer; a UI deve exibir indisponibilidade/consulta incompleta, nunca zeros ou resoluções falsas. Vulnerabilidades ausentes em consultas incompletas não alteram workflow.
10. Confirmar que uma CVE presente em vários agents/pacotes recebe os mesmos EPSS/percentile e KEV; validar datas, fonte e estado “sem score” sem converter ausência em zero.
11. Simular indisponibilidade/arquivo inválido em FIRST ou CISA: preservar último enrichment válido, marcá-lo como desatualizado e deixar a leitura Wazuh atual disponível.
12. Conferir filtros/contagens do dashboard por KEV e faixa EPSS com vulnerabilidades ao vivo agregadas por CVE; a consulta deve incluir todas as páginas e não apenas as linhas exibidas.
13. Invocar rotas e queries sem módulo e com tenant alterado manualmente: negar acesso no servidor/RLS.
14. Tentar atribuir `super_admin` e módulo a si mesmo por payload/UI: negar e auditar.
15. Salvar uma mudança de status/comentário e comprovar que a alteração é do PUS, identificada por ator e horário, sem mutar documento Wazuh.
16. Recarregar URL copiada, voltar no navegador e compartilhar deep link: manter página, tenant autorizado e filtros sem bypass.
17. Verificar contraste dos dois temas, labels de status que não dependam apenas da cor, foco, navegação por teclado, leitor de tela e erros claros.
18. Validar com analistas e gestores se “KEV ativo”, “EPSS ≥ corte” e “KEV + EPSS ≥ corte” comunicam claramente os critérios; os totais de KEV e EPSS podem se sobrepor, enquanto o terceiro indicador é a interseção.
19. Rever a fila em desktop, tablet e mobile: CVE/pacote e hostname legíveis, sem corte por overflow nem rolagem horizontal dentro do cartão; validar estados vazios e foco de linha clicável.

## Evidências e bloqueio de release

- Salvar resultado por build, versão/configuração Wazuh e migration/schema usados, com log sem credenciais nem dados excessivos.
- Bloquear release para qualquer falha em isolamento de tenant, MFA, autorização server-side, integridade do finding, tratamento de falha/partial da consulta ao vivo ou backup/restore.
- UAT deve aprovar contagens, definição de status e semântica temporal antes de declarar aderência à origem.
