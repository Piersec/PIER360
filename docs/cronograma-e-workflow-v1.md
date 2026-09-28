# Cronograma faseado — PUS PIER360 V1.0

## Objetivo e sequência

**Meta:** apresentar a V1 funcional em 10 dias úteis, contados da aprovação do plano. O trabalho segue duas etapas em ordem: construir e estabilizar a plataforma primeiro; em seguida, conectar os dados reais do Wazuh e enriquecer CVEs com EPSS/KEV.

Durante a construção das telas, o produto usa fixtures sintéticas por meio de um adaptador substituível. A etiqueta DEMO permanece visível para não confundir valores fictícios com dados de produção. A conexão com o Wazuh só começa depois do marco de conclusão das telas e dos fluxos principais.

**Equipe e dependências assumidas:** dois desenvolvedores full-stack, UX/produto e QA/segurança em dedicação parcial; projeto Vercel/Supabase de desenvolvimento pronto; acesso de leitura a Manager e Indexer não produtivos disponível até o Dia 6; amostras de dados autorizadas. Se houver apenas um desenvolvedor ou o acesso Wazuh atrasar, o prazo da apresentação integrada precisa ser revisto.

O Dia 10 é uma apresentação funcional em ambiente controlado, não autorização de go-live comercial. Produção depende dos gates de segurança, operação e aceite descritos no [plano de produção](./plano-de-producao.md).

## Escopo da apresentação V1

- Visão geral e distribuição de agents por estado.
- Busca/lista de agents e ficha com nome, IP, último contato e último scan de inventário.
- Dashboard e gestão de vulnerabilidades, detalhe por finding e workflow PUS.
- Super admin: usuários, tenant, status e permissões por módulo.
- Modo claro/escuro, layouts responsivos e estados de carregamento, vazio e erro.
- Login e controles de acesso previstos na V1: Supabase Auth, MFA TOTP, CAPTCHA Turnstile, isolamento por tenant e autorização no servidor.
- Leitura de agents via Wazuh Manager API; leitura atual de vulnerabilidades via Wazuh Indexer, índice `wazuh-states-vulnerabilities-*`.
- Enriquecimento EPSS e CISA KEV associado por CVE, com fonte e atualização visíveis.

Hardening/CIS, CTI próprio, alertas gerais/SIEM, SOAR, resposta remota e relatórios avançados seguem fora desta V1, conforme [escopo e critérios de aceite](./especificacao-v1.md).

## Cronograma de 10 dias úteis

| Dia | Fase | Entrega do dia | Marco/aceite |
|---:|---|---|---|
| 1 | Fundação da plataforma | Estrutura da aplicação e deploy preview; navegação; design tokens; layout responsivo; temas claro/escuro; contrato do adaptador de dados e fixtures DEMO. | Todas as rotas da V1 abrem com o mesmo shell e a origem fictícia está identificada. |
| 2 | Plataforma e acesso | Fluxos e telas de login/convite; configuração inicial de Supabase Auth, MFA/Turnstile; modelo de tenant, usuários e permissões por módulo; proteção de API/rotas. | Usuário de teste entra no ambiente de desenvolvimento; acesso é negado por padrão. |
| 3 | Módulo de agents | Resumo total/ativos/desconectados/pendentes, busca e lista, ficha com IP, último contato e scan Syscollector; classificação PUS binária “ativo crítico/não crítico”, sem score, usando o adaptador DEMO. | Fluxos de lista, filtro, classificação e detalhe prontos sem depender do Wazuh. |
| 4 | Módulo de vulnerabilidades | Dashboard, gestão/lista, filtros por CVE, severidade, KEV/EPSS e workflow; KEV precede EPSS, que ordena do maior para o menor; corte por tenant destaca EPSS ≥ limiar. | Dashboard, lista, filtro e detalhe usam o mesmo classificador; ativo crítico é exibido como contexto sem alterar scores nem prioridade. |
| 5 | Administração e fechamento de UI | Super admin para convidar/editar/desativar usuário, atribuir tenant e módulos; configuração do limiar EPSS por tenant; fluxo de tratamento, revisão de navegação e tema. | Alterar o limiar de um tenant atualiza suas telas sem afetar outro; telas da apresentação completas. |
| 6 | Gate de plataforma | QA funcional com dados DEMO; corrigir bloqueadores de UX; concluir autorização/RLS principal; ensaio das telas; validar conectividade e credenciais read-only do Wazuh fora do browser. | **Gate A:** produto/UI estável e aprovado para começar a integração de dados. |
| 7 | Integração Wazuh — agents | Conector server-side para Manager API; resumo de status, paginação e ficha; preservar status fonte; mapear `lastKeepAlive`; buscar o scan Syscollector conforme contrato instalado. | Totais e amostra de fichas reconciliados com a Manager API de teste. |
| 8 | Integração Wazuh — vulnerabilidades | Indexer API no backend consultando o índice States ao abrir dashboard/lista/detalhe; filtros e paginação no servidor; identidade estável da vulnerabilidade; horário/resultado da consulta; cruzamento com as marcações binárias de criticidade dos ativos para atualizar métricas. | Vulnerabilidades da UI correspondem à consulta atual do índice e preservam o overlay de criticidade por tenant/conexão/agent. Falha/timeout não vira zero nem resolução. |
| 9 | Enriquecimento e integração ponta a ponta | Importar EPSS em lote e CISA KEV por rotina agendada; cruzar por CVE no servidor; exibir data/fonte/frescor; validar workflow PUS separado do estado Wazuh. | Finding recebe EPSS/KEV válidos; dado ausente ou fonte atrasada fica explícito. |
| 10 | QA, UAT e apresentação | Regressão do escopo; verificação de autorização/tenant; revisão final de UI/UX e acessibilidade; ensaio com dados autorizados; roteiro, pendências e decisão sobre o próximo gate. | **Gate B:** apresentação V1 realizada e pendências para piloto/produção registradas. |

## Paralelismo e rotina de trabalho

Nos Dias 1–6, dividir o trabalho entre (A) shell, componentes e telas e (B) Supabase Auth, tenant, RLS e contratos de dados. A partir do Gate A, dividir (A) Manager API/agents e (B) Indexer/vulnerabilidades; enrichment e QA integram os dois resultados. Manter uma única branch principal protegida e branches curtas por entrega.

1. No início de cada dia, confirmar a história, seu aceite e impedimentos.
2. Abrir pull request pequeno com captura/descrição da tela, mudança de contrato e evidência dos testes relevantes.
3. Revisar lógica de tenant e privilégios em toda mudança de autorização; credenciais Wazuh ficam somente no serviço server-side.
4. Fazer demonstração interna curta ao final do dia e registrar defeitos com prioridade e responsável.
5. Não iniciar a etapa Wazuh antes do Gate A; usar somente fixtures claramente marcadas até então.

## Próximas fases a partir do protótipo revisado

O protótipo já cobre navegação, dashboard, lista/ficha de ativos, gestão de vulnerabilidades e controles administrativos simulados. O próximo passo é aceitar os critérios funcionais e iniciar a fundação integrada; a demonstração atual ainda não está pronta para produção.

1. **Aceite do protótipo e escopo:** validar nomes dos indicadores, precedência KEV → EPSS, fluxo do analista e campos que permanecem na tela. Registrar decisões e congelar o escopo V1.
2. **Fundação segura:** configurar ambientes Vercel/Supabase; modelar tenants, usuários, módulos, workflow e auditoria; implementar sessão, MFA/Turnstile, autorização server-side e RLS. Nenhum dado Wazuh chega ao browser diretamente.
3. **Integração de ativos:** conector somente leitura da Manager API para resumo, lista, ficha, `lastKeepAlive` e scan Syscollector; validar paginação e contrato da versão instalada.
4. **Vulnerabilidades e enriquecimento:** serviço server-side consulta States ao abrir dashboard/lista/detalhe; persiste somente workflow do PUS; enriquece por CVE com EPSS diário e CISA KEV a cada 6 horas; mostra frescor e estado de erro/ausência.
5. **UI/UX sobre dados reais:** com os contratos estabilizados, observar analistas usando staging. Rever densidade e leitura da fila sem rolagem horizontal, clareza de filtros/contagens, estados vazios e de erro, responsividade, contraste, teclado/leitor de tela. Priorizar correções antes do UAT, sem expandir o escopo funcional por conveniência visual.
6. **QA, UAT e produção:** executar regressão funcional, isolamento tenant/módulo, segurança, reconciliação com Wazuh, backup/restore e observabilidade; fazer piloto limitado após aceite. Só então avaliar go-live.

O detalhamento executável da fase 2, com subfases, gates, matriz de autorização e dependências atuais, está em [Fase 2 — Fundação do backend](./fase-2-fundacao-backend.md). No DEV, o tenant Piersec e o primeiro Super Admin foram provisionados; o convite foi concluído definindo senha e MFA, e o usuário confirmou o primeiro acesso AAL2. Supabase Auth, Turnstile e permissões administrativas estão configurados no Preview. As oito migrations esperadas constam no banco DEV.

**Estado em 2026-09-26:** o bootstrap e o primeiro login foram concluídos. O Gate 2.8 ainda requer a evidência dos casos negativos de autorização/RLS e a revisão de dois avisos do Security Advisor antes do gate de produção: execução autenticada da rotina de concessão multi-tenant (protegida por verificação de super admin) e proteção contra senhas vazadas desabilitada. O projeto DEV não tem conexão Wazuh cadastrada. A fase seguinte começa pelo contrato e pelo conector server-side de leitura; consultas reais só serão ativadas depois de disponibilizar gateway, versão do Wazuh e credenciais read-only. Não publicar em Production nesta etapa.

### Execução atual — integração Wazuh (fases 3 e 8)

1. **Contrato e segurança:** concluída a correção do endpoint de contagens (`GET /agents/summary`) e documentado o contrato BFF↔gateway em [`wazuh-gateway-contract-v1.md`](./wazuh-gateway-contract-v1.md). `GET /agents/summary/status` não será usado para as métricas dos cartões.
2. **Data binding dos ativos:** implementados no app server-side a distribuição, listagem paginada e ficha do agente, com autorização AAL2 por tenant; a criticidade é um overlay binário auditado no PUS. `npm run typecheck:platform` e `npm run build:platform` passaram no workspace.
3. **Data binding de vulnerabilidades:** adicionados serviço server-side e tela de vulnerabilidades que consultam resumo por severidade e lista paginada do índice States através do gateway tipado. A tela exige AAL2/grant por tenant, associa overlay do workflow PUS por `findingKey` e distingue estado indisponível de zero. `npm run typecheck:platform` e `npm run build:platform` passaram no workspace.
4. **Conexão real em DEV:** a subfase local do gateway para Indexer está implementada e os testes unitários, typecheck e build passaram. Acesso direto ao Indexer foi validado no Wazuh com a identidade read-only: endpoint raiz e busca no States respondem autorizados; mappings e campos foram conferidos. Continua pendente implantar o gateway HTTPS na rede Docker, configurar CA/segredos por arquivo, ligar Cloudflare Tunnel → gateway, cadastrar a conexão ativa no tenant e validar as rotas reais pelo Preview. Até isso acontecer, as telas mostram “não configurada” e não simulam dados.
5. **Gate de dados reais:** após conectividade, reconciliar estados, paginação, `lastKeepAlive`, `scan.time`/`scan_time`, contagens por severidade, filtros e identidade agente+CVE+pacote com uma instância não produtiva. EPSS/KEV e a ordenação KEV → EPSS permanecem para a fase de enriquecimento.

**Estado em 2026-09-27:** o usuário Indexer `pier360_pus` já foi associado à regra `pier360_ro` e o privilégio de monitoramento do cluster necessário ao endpoint raiz foi incluído. O `GET /` e a busca no índice `wazuh-states-vulnerabilities-*` responderam com autorização; a consulta States confirmou 99 documentos. O gateway agora tem rotas tipadas de resumo e página para vulnerabilidades, separa as credenciais Manager/Indexer, exige TLS validado e rejeita resultados parciais. `npm run test:gateway` (8 casos), `npm run typecheck:platform` e `npm run build:platform` passaram. Não houve mudança de banco e nenhuma migration é necessária nesta subfase.

## Plano de testes por fase

- **Dias 1–2:** navegação, layout em viewport móvel/desktop, tema, login, MFA/CAPTCHA e negação de acesso por perfil/tenant.
- **Dias 3–5:** filtros e busca, totais, detalhe do agent/finding, obrigatoriedade de justificativa, atribuição/comentários, permissões do super admin e persistência do workflow.
- **Dia 6:** revisão da UI, testes de autorização/RLS e matriz de aceite antes de trocar a fonte de dados.
- **Dias 7–8:** contratos Manager/Indexer, paginação, autenticação read-only, timeout/401/403/429/5xx, timestamps e reconciliação de amostras. Indexer parcial/falha nunca é exibido como zero ou como resolução.
- **Dia 9:** junção por CVE, EPSS ausente, KEV válido/atrasado, repetição idempotente da ingestão e preservação do último enrichment bom em falha.
- **Dia 10:** regressão ponta a ponta, isolamento tenant/módulo, tema e responsividade, UAT e teste do roteiro de apresentação.

O [plano de testes](./plano-de-testes.md) mantém os casos detalhados, evidências e critérios de go/no-go. Os dados sintéticos são usados só antes da integração; a apresentação deve identificar claramente quando uma fonte real estiver indisponível.

## Workflow de vulnerabilidade

1. O backend lê os findings atuais do índice States do Wazuh; cada registro mantém conexão, agent, CVE, pacote/versão, identidade de origem e horário/resultado da consulta.
2. O backend associa EPSS e KEV pelo CVE e registra fonte e frescor. Não faz chamada externa por finding.
3. O PUS guarda separadamente status de tratamento, responsável, comentário e auditoria, ligados à identidade estável do finding.
4. Analista move o work item entre **Sem tratamento**, **Atribuída**, **Em correção** e **Correção aplicada**. **Risco aceito** e **Falso positivo** requerem justificativa.
5. Ausência em uma consulta, falha parcial ou timeout não encerra o finding nem apaga o work item. Somente uma regra de resolução validada para a versão Wazuh poderá alterar a interpretação do estado de origem.

## Pós-apresentação e produção

Após o Dia 10, estabilizar findings em staging e concluir os itens que não couberem no corte. Antes de produção: revisão independente das políticas RLS e das APIs, MFA e recuperação de conta, segredo/rotação de credenciais, teste de carga, rate limits, logs/alertas, backup/restore, runbooks, custo/limites de Vercel e Supabase, piloto com tenant limitado e aceite explícito de go/no-go. A conexão Wazuh permanece somente leitura.

### API externa do PIER360 — fase futura, fora da V1

A API de integração do PIER360 será detalhada após a estabilização da V1 e dos contratos de dados. Primeiro serão definidos casos de uso, contrato OpenAPI/versionamento, identidade máquina-a-máquina, escopos tenant/módulo, credenciais rotativas, rate limits e auditoria para atores de integração. A primeira entrega priorizará consultas de leitura; alterações de workflow do PUS serão uma entrega posterior com idempotência. Ações no Manager, como remoção de agente, exigirão uma etapa separada de autorização, execução assíncrona, retries e reconciliação.

Para evitar reestruturação, a lógica de negócio e as regras de autorização ficam em serviços server-side compartilháveis entre a UI e a futura API. A API não adiciona trabalho ao Gate 2.8, não altera a leitura somente do Wazuh na V1 e não entra no prazo de apresentação de 10 dias. Migrations e testes específicos de identidades de integração serão criados quando essa fase for aprovada.

## Aprovação e responsabilidades

- **Produto:** prioriza pendências e dá aceite de apresentação/UAT.
- **Desenvolvimento:** entrega telas, APIs e migrations seguindo os gates.
- **Segurança/Plataforma:** fornece contas de serviço read-only, revisa RLS, exposição de rede, segredos e gate de produção.
- **QA:** mantém evidências dos testes e bloqueia a apresentação caso os critérios críticos de isolamento ou fidelidade de dados falhem.

## Referências

- [Escopo e critérios de aceite](./especificacao-v1.md)
- [Arquitetura e roadmap técnico](./arquitetura-e-roadmap.md)
- [Plano de testes](./plano-de-testes.md)
- [Plano de produção](./plano-de-producao.md)
- [Skill interna de integração Wazuh](../.agents/skills/wazuh-pus-integration/SKILL.md)
