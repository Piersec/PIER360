# PUS PIER360 — Escopo e critérios de aceite da V1.0

## Objetivo

Entregar uma primeira versão multi-tenant para visibilidade de agentes Wazuh e gestão de vulnerabilidades, com controle de acesso por módulo. O PUS consulta os dados atuais do Wazuh no carregamento das telas e mantém seu próprio workflow de tratamento; não pretende substituir o SIEM.

## Incluído na V1.0

1. **Resumo de agentes:** total, ativos, desconectados e pendentes. Consultar a Manager API e mostrar o horário da consulta e a saúde/atraso da conexão Wazuh.
2. **Lista e ficha do agente:** busca por nome/IP, status, nome, IP, identificador Wazuh, sistema operacional, último contato e último scan do inventário de software Syscollector. O último contato vem de `lastKeepAlive`; o scan vem de `scan.time` (ou do alias de resposta validado para a versão, como `scan_time`). Não chamar esse valor de scan de vulnerabilidades. No detalhe, usuário autorizado pode marcar o ativo como crítico ou não crítico; é uma classificação binária operacional do PUS, sem score/peso numérico. A lista mostra a classificação; na tabela de ativos impactados do dashboard ela aparece como contexto, sem cartão dedicado nem alteração dos scores de risco.
3. **Dashboard de vulnerabilidades:** totais por severidade, três indicadores visíveis — KEV ativo + EPSS no corte, KEV ativo e EPSS no corte — e filtros que abram a lista já filtrada. Os indicadores KEV e EPSS podem se sobrepor; o indicador combinado é a interseção. A regra por tenant é: vulnerabilidades no CISA KEV vêm primeiro; na sequência, ordenar EPSS válido do maior para o menor. EPSS abaixo do corte segue na lista; EPSS ausente fica pendente e nunca vira zero. O corte padrão é 8,8% e inclui igualdade (`EPSS ≥ 8,8%`). CVSS/severidade e criticidade do ativo são exibidos como contexto e não alteram a ordem. Consultar o índice `wazuh-states-vulnerabilities-*` do Indexer em cada requisição de leitura e juntar enriquecimentos atualizados separadamente por CVE. Distinguir dado indisponível de zero e apresentar horário/estado da consulta e atualização das fontes de enriquecimento.
4. **Gestão de vulnerabilidades:** busca e filtros por CVE, pacote, agente, severidade e estado; detalhe de CVE/pacote e hosts impactados; workflow de tratamento persistido pelo PUS (por exemplo: Sem tratamento, Atribuída, Em correção, Correção aplicada, Risco aceito, Falso positivo), comentários e responsável. A detecção atual vem da consulta ao índice States; o workflow do PUS fica separado e é ligado por identidade estável do documento/finding.
5. **Super admin:** criar/convidar e desativar acesso, atribuir tenant, editar permissões e visualizar estado da conta. Habilitar módulos de tela por usuário (Visão geral, Agentes, Dashboard de vulnerabilidades, Gestão de vulnerabilidades). Ajustar por tenant o limiar EPSS da fórmula de priorização, com padrão de 8,8%, validação de faixa e auditoria. Negar acesso por padrão. Registrar alterações de privilégio e fórmula em trilha de auditoria.
6. **Login e UX:** convite sem cadastro público, CAPTCHA Turnstile, MFA TOTP, sessão protegida, modo claro/escuro, navegação responsiva, estados acessíveis e linguagem consistente em português.

## Fora de escopo da V1.0

Alertas gerais e investigação SIEM, Hardening/CIS, módulos de CTI próprios, catálogo de integrações, SOAR/DFIR/LLM, ações remotas no Wazuh, gestão de usuários por tenant, relatórios avançados e IA. Preparar contratos e limites modulares para que possam ser adicionados depois sem carregar sua UI ou permissões antes da hora.

## Regras de domínio essenciais

- **Agent:** obter distribuição em `GET /agents/summary` (`data.status`); normalizar `active` → Ativo, `disconnected` → Desconectado e `pending`/`never_connected` → Pendente. Preservar status fonte. `GET /agents/summary/status` não alimenta os cartões de distribuição.
- **Criticidade operacional do ativo:** é um campo booleano do PUS, separado do documento Wazuh e dos scores de risco. Na integração, persistir por tenant/conexão/agent e auditar alterações autorizadas. A marcação aparece na lista/ficha de ativos e como contexto na tabela de ativos impactados; não altera métricas de priorização nem soma pontos ao risco calculado.
- **Prioridade de vulnerabilidades:** usar um único classificador compartilhado por dashboard, lista, filtros, ficha e ativos. Vulnerabilidade no KEV vem primeiro, mesmo com EPSS baixo; as demais são ordenadas pelo EPSS válido em ordem decrescente. A partir do corte do tenant (padrão 8,8%, inclusivo), destacar EPSS alto; abaixo do corte, manter a vulnerabilidade na fila; sem EPSS válido, marcar como pendente. A interface usa os critérios descritivos “KEV ativo”, “EPSS ≥ corte” e “KEV ativo + EPSS ≥ corte”, sem códigos de prioridade sequenciais. Não somar pesos de CVSS, severidade ou criticidade do ativo a esse cálculo.
- **Ligação de dados:** cada tela consome modelos de leitura do adaptador, que deriva métricas e filtros dos mesmos registros e da configuração do tenant. A integração move essa agregação para o BFF/server-side; a UI não mantém cópias independentes de métricas nem recalcula regras diferentes por página.
- **Último contato e scan:** obter dados do agente na Manager API, com `lastKeepAlive` para o último contato. Consultar `GET /syscollector/{agent_id}/packages` para o timestamp de scan do inventário (`scan.time` nos exemplos atuais; validar o formato exato por versão). Não confundir nenhum deles com `vulnerability.detected_at` ou horário de leitura do PUS.
- **Vulnerabilidades atuais:** consultar o padrão `wazuh-states-vulnerabilities-*` na Indexer API diretamente pelo backend a cada requisição do produto. “Em tempo real” significa leitura do estado indexado no momento da consulta; a atualização continua condicionada às cadências de coleta, processamento e indexação do Wazuh.
- **Workflow:** persistir no PUS apenas estado operacional, comentários, responsável e auditoria, ligados a uma identidade estável. Ausência em consulta ou erro parcial do Indexer não fecha findings nem remove histórico de tratamento.
- **Finding:** iniciar com grão agente + CVE + pacote/versão (confirmar a chave real no cluster), não apenas CVE; uma mesma CVE pode afetar pacotes/hosts diferentes.
- **Enriquecimento de risco:** a V1 inclui EPSS (score e percentile publicados pela FIRST) e presença no CISA KEV, associados por CVE. Manter severidade/CVSS do Wazuh separados desses sinais; informar fonte/data de cada conjunto. EPSS ausente e fonte desatualizada são estados próprios, nunca score zero ou KEV falso por falha de atualização.
- **Resolução:** não fechar workflow do PUS por finding ausente numa página, timeout, consulta parcial ou falha. Refletir resolução de origem apenas após consultar o estado atual em escopo completo e validar a semântica de resolução da versão Wazuh; workflow de tratamento permanece independente.
- **Tenancy:** todo dado de origem ligado a uma conexão Wazuh cadastrada sob um tenant; usuário recebe acesso apenas aos tenants e módulos concedidos. Super admin é uma permissão global explícita e auditada.

## Critérios de aceite

- Os totais de `GET /agents/summary` fecham com a resposta da origem; `pending` e `never_connected` aparecem no grupo Pendente sem perder distinção no dado fonte.
- A ficha exibe nome, IP, último contato (`lastKeepAlive`) e último scan Syscollector (`scan.time`/campo equivalente validado), com fuso/UTC claro e origem/horário da consulta.
- Usuário autorizado pode marcar/desmarcar “Ativo crítico” na ficha; a seleção é binária e persiste no PUS. A classificação aparece na lista/ficha e como contexto dos ativos impactados; não recebe pontuação nem cartão dedicado no dashboard.
- O limiar EPSS editado pelo super admin fica isolado por tenant; salvar um novo valor atualiza totais, indicadores, ordenação do dashboard, lista e filtros desse tenant. KEV mantém precedência, EPSS ausente continua pendente, e tenants diferentes não compartilham a configuração.
- Dashboard, filtros, lista e detalhe usam o estado consultado do mesmo índice States e definições coerentes; falha/timeout/consulta incompleta não aparece como zero nem como finding resolvido.
- Dashboard e lista executam consultas autorizadas no Indexer; paginação/filtros do servidor não se limitam à página já carregada no browser. O detalhe apresenta agente, CVE, pacote/versão, severidade, datas da origem e workflow do PUS.
- Vulnerabilidades com a mesma CVE recebem o mesmo EPSS/KEV da última atualização válida. Exibir score, percentile, membership KEV e data das fontes; dados ausentes/desatualizados ficam identificados e não bloqueiam a leitura atual do Wazuh.
- Alterar workflow/comentário gera trilha com usuário e horário, sem editar o estado original do Wazuh.
- Usuário sem módulo não consegue abrir a tela nem ler os dados chamando diretamente a API; usuário de outro tenant não consegue ver nem alterar esses registros.
- O super admin pode convidar, atribuir tenant e módulos; usuário sem permissão global não consegue criar super admins ou alterar as próprias permissões.
- MFA TOTP é exigido e verificado no servidor para abrir páginas/APIs protegidas; CAPTCHA inválido/expirado não autentica.
- Tema claro e escuro mantêm contraste, labels de severidade e estado, navegação por teclado e layouts utilizáveis em viewport menor.
- Links, URLs, recarregamento e voltar preservam a página/consulta e os filtros essenciais.

## Suposições a confirmar no kickoff técnico

- Versão de Wazuh e topologia (self-hosted, cloud ou vários clusters), existência de ambientes não produtivos e forma autorizada de conectividade.
- Volume máximo por tenant de agents/findings/CVEs distintas, ritmo de atualização do Wazuh e das fontes EPSS/KEV, retenção e política de dados.
- Compatibilidade e semântica do `scan.time`/`scan_time` na API instalada, regra autoritativa de resolução e volume/limites de consulta ao Indexer.
- Se usuários terão um ou vários tenants; quem pode atribuir tratamento e aprovar risco aceito.
- Região e planos Vercel/Supabase para dados de segurança em produção.

