# Fase 2 — Fundação do backend, acesso e auditoria

## Objetivo

Implementar a fundação segura da V1 antes de conectar o Wazuh. O protótipo atual continua como referência visual e modo DEMO até a nova camada estar operacional. Nenhum dado Wazuh ou segredo deve passar pelo browser.

## Subfases e gates

| Subfase | Entrega | Critério para concluir | Situação |
|---|---|---|---|
| 2.0 — Preparação técnica | Auditar o projeto, confirmar arquitetura, escopo V1 e dependências externas. | Aplicação e dependências identificadas; sem alterações remotas inadvertidas. | Concluída nesta rodada. |
| 2.1 — Ambiente e esqueleto server-side | Criar app/API server-side para Vercel, ambientes local/preview/staging, validação de variáveis e cliente Supabase SSR. Preservar o protótipo DEMO durante a transição. | Preview responde; URL/chaves ausentes falham com mensagem segura; nenhum segredo no bundle ou repositório. | App Next.js separado em `apps/platform`, cliente SSR, refresh de sessão via `proxy.ts`, callback PKCE e páginas dinâmicas protegidas implementados. Vercel usa `apps/platform` com preset Next.js; o alias estável `piersec-pier360-git-preview-v1-davidbasile2000-4092s-projects.vercel.app` serve `/login`. URL e chave publishable do Supabase e `PIER360_APP_URL` estão limitadas à branch Preview `preview-v1`. O deploy Production existente e o protótipo em `apps/web` foram preservados. |
| 2.2 — Modelo de identidade e tenant | Criar migrations para `tenants`, `profiles`, `tenant_memberships`, capacidades globais e `user_module_permissions`. Formalizar chaves, constraints, índices e exclusão/desativação lógica. | Um usuário só alcança tenants associados; permissões ausentes são negadas; super admin não depende de metadata editável. | 10 tabelas e constraints aplicadas ao DEV; sem tenant ou usuário inicial. |
| 2.3 — RLS e grants | Ativar RLS em todas as tabelas de domínio; escrever policies por operação com `USING` e `WITH CHECK`; conceder acesso à Data API apenas onde necessário. | Isolamento A/B, acesso anônimo e escrita fora do tenant negados; revisão de policies e grants aprovada. | RLS/grants aplicados; suspensão do tenant desativa grants de módulo para os membros; advisor de segurança sem lints. Testes A/B ainda pendentes porque o DEV não tem tenants ou usuários de teste. |
| 2.4 — Supabase Auth e MFA | Login sem cadastro público, aceite de convite, recuperação de acesso, sessão SSR e TOTP. Exigir AAL2 para páginas/ações protegidas e administrativas. | AAL1 não passa por rotas protegidas; AAL2 válido passa; sessão expirada encerra acesso. | Login, recuperação de senha, callback PKCE, ativação de convite confirmado, cadastro/verificação TOTP e desafio MFA implementados. O DEV tem TOTP habilitado e limite da sessão AAL1 ativo; o fluxo de ponta a ponta ainda não foi testado porque não há usuários. |
| 2.5 — Turnstile e proteção de acesso | Configurar CAPTCHA no Auth e integrar o widget aos fluxos cobertos. Adicionar limites para login, recuperação e endpoints sensíveis. | Token inválido/expirado impede a operação; segredo Turnstile fica apenas no Supabase; erro não revela se a conta existe. | Widget integrado ao login e à recuperação, com bloqueio fail-closed sem site key. No Supabase DEV, CAPTCHA está habilitado com Turnstile e a chave secreta está salva no Auth. A site key está como Config em Vercel Preview, branch `preview-v1`; o widget `PIER360 DEV` permite o alias estável Preview e o domínio Production. O login Preview mostra Turnstile validado. O Auth tem limite padrão de login; rate limits para ações/endpoints próprios seguem pendentes. |
| 2.6 — BFF e autorização por módulo | Implementar guards server-side para sessão, AAL, membership, tenant e capability antes de cada operação. Manter o acesso ao Manager/Indexer fora do escopo desta fase. | Uma capability ausente bloqueia a API; o cliente não consegue trocar tenant, connection ou escopo para obter dados de outro tenant. | Guards reutilizáveis exigem identidade válida, AAL2 e grant do módulo; inclui bypass controlado para Super Admin. As Server Actions de administração conferem AAL2 e a capability novamente. Integrações Wazuh e suas rotas continuam fora desta fase. QA de isolamento permanece pendente. |
| 2.7 — Auditoria e operações administrativas | Registrar ator, tenant, ação, alvo, instante e mudanças essenciais ao convidar/desativar usuários e alterar memberships/grants. | Alterações privilegiadas deixam trilha consultável; secrets, tokens e payloads integrais não são registrados; ninguém promove a si próprio. | Tela de Super Admin permite convidar, definir papel, habilitar telas e nível de acesso, editar/desativar membership e consultar os últimos 50 eventos. Tabela/triggers auditam as alterações. Primeiro Super Admin, variável server-side da Admin API e QA dos fluxos ainda pendentes. |
| 2.8 — Gate da fundação | Executar revisão de segurança, testes de isolamento e fluxos de Auth; corrigir bloqueadores; preparar preview de staging. | Matriz de acesso aprovada, policies revisadas e Auth/MFA/CAPTCHA funcionais. Só então liberar integrações Wazuh. | Em andamento (2026-09-26): Preview Next.js implantado; callback exato do alias Preview está na allowlist do Supabase; rotas protegidas redirecionam para `/login` sem sessão; Turnstile Preview validado. Gate ainda aberto: bootstrap controlado do tenant/Super Admin, configuração da Admin API server-side para Preview e testes dinâmicos de Auth/MFA e isolamento A/B. |

### Evidências iniciais do Gate 2.8 (baseline anterior à implantação do Preview) — 2026-09-26

- **Aplicação local:** `npm --prefix apps/platform run typecheck` e `npm --prefix apps/platform run build` passaram. Sem sessão, `/dashboard` e `/admin/users` redirecionam para `/login`; login e recuperação mostram o bloqueio fail-closed do Turnstile sem configuração.
- **Exposição de segredos:** varredura dos bundles cliente de produção não encontrou nome de variável nem padrão de chave secreta Supabase. A variável privilegiada não está configurada no ambiente local.
- **Supabase DEV (`pier360-dev`):** status Healthy; painel mostra zero issues nos advisors; MFA TOTP Enabled e limitação de sessão AAL1 ativa; limites de Auth padrão presentes.
- **Configuração incompleta:** não há usuários ou tenant inicial; CAPTCHA Auth está Disabled; Site URL está em `http://localhost:3000`. O callback `http://localhost:3000/auth/callback` foi adicionado à allowlist. O ambiente local tem `PIER360_APP_URL=http://localhost:3000`, mas ainda não tem site key Turnstile nem chave server-side Admin API; o domínio de staging/callback de staging também falta.
- **Gate ainda não aprovado na vistoria inicial:** sem domínio/Preview e identidade inicial, não era possível validar callbacks reais, CAPTCHA válido/inválido, convite + MFA, AAL1/AAL2 com usuário, nem isolamento entre dois tenants. Não foram criados dados de teste nem feitas alterações remotas naquela vistoria.

### Atualização do Preview — 2026-09-26

- **Vercel:** Root Directory `apps/platform` e preset Next.js. Deploy Preview da branch `preview-v1` está Ready no alias estável `https://piersec-pier360-git-preview-v1-davidbasile2000-4092s-projects.vercel.app`; o deploy Production atual não foi promovido nem substituído.
- **Ambiente Preview:** `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` e `PIER360_APP_URL` limitadas à branch `preview-v1`. `SUPABASE_SECRET_KEY` continua somente em Production; nenhuma chave privilegiada foi copiada para Preview.
- **Supabase Auth:** Site URL `https://piersec-pier360.vercel.app`; callbacks local e Production preservados; callback Preview exato `https://piersec-pier360-git-preview-v1-davidbasile2000-4092s-projects.vercel.app/auth/callback` adicionado.
- **Turnstile:** `NEXT_PUBLIC_TURNSTILE_SITE_KEY` está como Config somente no Preview da branch `preview-v1`. O widget Cloudflare `PIER360 DEV` autoriza `piersec-pier360-git-preview-v1-davidbasile2000-4092s-projects.vercel.app` e `piersec-pier360.vercel.app`. A tela de login Preview foi aberta e mostrou o estado Turnstile “Sucesso!” e o botão de login habilitado.
- **Smoke manual sem sessão:** `/dashboard` e `/admin/users` redirecionam a `/login`. Fluxo sem sessão continua negado; ainda não foi feito login real ou validação de MFA/RLS com uma conta.

Para continuar, definir o e-mail corporativo do primeiro Super Admin e o nome/slug do tenant DEV. A criação inicial é um bootstrap excepcional porque a tela de convites exige um Super Admin existente; o procedimento pronto está em [Bootstrap do primeiro Super Admin DEV](./bootstrap-primeiro-super-admin-dev.md). O projeto ainda não tem tenant nem usuário PIER360 inicial. Depois do bootstrap, configurar a chave Admin API do projeto DEV como `SUPABASE_SECRET_KEY` server-side somente no Preview `preview-v1` para habilitar a tela de administração. Não colocar essa chave em `NEXT_PUBLIC_*`, em Config, no Git ou nesta conversa. Em seguida executar a matriz Auth/MFA/RLS com usuários de teste em tenants separados.

**Limite de escopo:** a API externa do PIER360 foi registrada como evolução pós-V1 em [Arquitetura e roadmap](./arquitetura-e-roadmap.md). O Gate 2.8 não inclui endpoints para integrações externas, credenciais máquina-a-máquina ou ações de escrita no Manager. A preparação é manter a lógica de domínio separada do BFF; a API terá fase e aceite próprios depois da estabilização dos contratos de dados V1. Isso preserva o cronograma atual.

## Ordem sugerida no cronograma de 10 dias

- Dias 1–2: subfases 2.1–2.3 — ambiente, schema e RLS.
- Dias 2–3: subfases 2.4–2.5 — Auth, MFA e Turnstile.
- Dias 3–5: subfases 2.6–2.7 — BFF, autorização, administração e auditoria.
- Dia 6: subfase 2.8 — gate da fundação e staging.

Essa estimativa mantém a premissa original de ambiente disponível e duas pessoas técnicas em paralelo. O cronograma deve ser recalculado se a criação/conexão do projeto, configuração de domínio/Turnstile ou provisionamento de conta atrasar. Não iniciar Manager API nem Indexer antes do gate.

## Modelo mínimo a migrar

- `tenants`: organizações clientes e estado.
- `profiles`: extensão de `auth.users`, sem senha ou token.
- `tenant_memberships`: vínculo ativo usuário/tenant e papel operacional.
- `global_capabilities`: privilégios globais, incluindo super admin, atribuídos apenas por ação administrativa controlada.
- `user_module_permissions`: permissões explícitas por usuário, tenant, módulo e capability; ausência de grant significa negar.
- `wazuh_connections`: metadados de conexão por tenant; segredos ficam num secret store, fora de tabelas consultáveis pela Data API.
- `asset_classifications`: overlay binário `is_critical` ligado a tenant, conexão e agent; sem pontuação.
- `tenant_vulnerability_priority_configs`: limiar EPSS por tenant; precedência de KEV permanece fixa pelo produto.
- `vulnerability_work_items`: estado/responsável/comentários PUS, sem cópia do finding Wazuh.
- `audit_log`: histórico de alterações autorizadas.

Toda tabela de domínio deve ter `tenant_id` direto ou chegar ao tenant por chave estrangeira validável na policy. Usar constraints compostas quando necessário para impedir que uma linha de um tenant aponte para uma entidade de outro. RLS não substitui grants: a exposição pela Data API deve ser explícita, por tabela e papel.

## Regra obrigatória para mudanças de banco

Cada mudança lógica de schema, função, policy/RLS, grant, índice ou constraint deve ter sua própria migration versionada em `supabase/migrations/`. Não deixar DDL persistente aplicado apenas pelo Dashboard. Gerar o arquivo pelo Supabase CLI, revisar o SQL e só então aplicá-lo ao projeto DEV:

```powershell
$taskSupabaseHome = Join-Path $env:TEMP 'pier360-supabase-home'
New-Item -ItemType Directory -Force -Path $taskSupabaseHome | Out-Null
$oldProfile = $env:USERPROFILE
$oldDrive = $env:HOMEDRIVE
$oldPath = $env:HOMEPATH
$env:USERPROFILE = $taskSupabaseHome
$env:HOMEDRIVE = ''
$env:HOMEPATH = $taskSupabaseHome
npx --no-install supabase migration new descricao_curta_da_mudanca
$env:USERPROFILE = $oldProfile
$env:HOMEDRIVE = $oldDrive
$env:HOMEPATH = $oldPath
```

Depois da aplicação no DEV, conferir o histórico remoto e os advisors; atualizar `database.types.ts` se o contrato do banco mudou. Manter arquivo e versão do histórico sincronizados. A mesma sequência versionada só segue para produção após QA/UAT e aprovação do gate de produção. O CLI desta versão ignora `SUPABASE_HOME` no Windows; a substituição temporária de `USERPROFILE`, `HOMEDRIVE` e `HOMEPATH` acima vale apenas para esse processo PowerShell e evita criar `C:\Users\...\.supabase` ou gravar configuração global.

## Matriz mínima de autorização

| Identidade/sessão | Dados do tenant associado | Outro tenant | Administração global |
|---|---|---|---|
| Anônimo | Negado | Negado | Negado |
| Autenticado sem membership | Negado | Negado | Negado |
| Membro sem capability do módulo | Somente módulos explicitamente concedidos | Negado | Negado |
| Membro em AAL1 | Apenas enrollment/verificação de MFA e saída; dados e ações do app bloqueados | Negado | Negado |
| Membro em AAL2 | Ações permitidas por membership + capability | Negado | Negado |
| Super admin autorizado em AAL2 | Conforme escopo administrativo auditado | Conforme capability global, com tenant-alvo explícito | Permitido e auditado |

As mesmas verificações devem existir nas APIs server-side e no banco. Não usar `user_metadata` como fonte de roles/grants. `auth.uid()` identifica o ator; entitlement e tenant-alvo vêm de tabelas confiáveis. Em toda policy de escrita, revisar tanto `USING` quanto `WITH CHECK`.

## Fluxos de autenticação

1. Sem auto cadastro. Super Admin autorizado inicia convite pela Admin API server-side; nunca chamar Admin API ou expor chave `sb_secret_...` no browser. `SUPABASE_SECRET_KEY` existe somente como variável server-side no ambiente local/Vercel.
2. Login e recuperação enviam o `captchaToken` do Turnstile à Supabase Auth, com CAPTCHA ativado no projeto.
3. Usuário cadastra/verifica fator TOTP; a aplicação confere o nível de assurance antes de servir rotas protegidas. Ações administrativas exigem AAL2.
4. A camada server-side valida a identidade no Auth, busca perfil, membership e grants no banco e só então resolve tenant e executa a operação.
5. Saída, revogação/desativação e expiração invalidam o acesso server-side. Erros de login e recuperação não confirmam a existência de um e-mail.

## Requisitos de aceite do gate 2.8

- Usuário A não consegue selecionar, listar, criar, alterar ou excluir linhas do tenant B, mesmo manipulando URL, parâmetros e corpo da API.
- Usuário não consegue conceder a si mesmo super admin, membership, módulos ou capabilities.
- Módulo sem grant e endpoint sem sessão são negados no servidor, ainda que a UI exponha uma chamada manual.
- Rotas privilegiadas rejeitam sessão AAL1 e aceitam apenas AAL2 verificado.
- CAPTCHA inválido, ausente ou expirado bloqueia o fluxo configurado.
- Cada mutação administrativa e de workflow registra ator, tenant, alvo e mudança essencial.
- Nenhum secret/service-role/Turnstile secret é incluído no HTML, bundle, logs ou repositório.
- Configuração de tenants diferentes não se mistura; as telas continuam com o mesmo modelo de autorização e fonte de verdade.
- QA de políticas inclui leitura e escrita (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) para anon, usuário sem membership, tenant correto, tenant diferente e super admin.

## Dependências externas já verificadas

- O protótipo estático permanece em `apps/web`. O novo app server-side fica isolado em `apps/platform`, com dependências fixadas e lockfile; ele não substitui o modo DEMO.
- `pier360-dev` foi criado na organização `Piersec-Ciberseguranca`, região `sa-east-1`, plano Free; status reportado como saudável.
- Supabase CLI `2.117.0` está fixado no `package.json` e lockfile. `supabase init` gerou a configuração; migrations são geradas pelo CLI e sincronizadas com o histórico do DEV.
- As seis migrations `20260926003902_foundation_identity_tenancy_access_audit`, `20260926004045_optimize_rls_policy_groups_and_fk_indexes`, `20260926010414_enforce_active_tenant_module_access`, `20260926032146_member_access_admin_workflows`, `20260926032442_make_admin_routines_invoker_safe` e `20260926032549_consolidate_pending_activation_policies` estão aplicadas no DEV. Todas as dez tabelas de domínio têm RLS; o advisor de segurança retorna sem lints e o de desempenho não tem WARN, apenas INFO para índices não utilizados num banco ainda vazio.
- O CLI cria migrations com perfil de usuário redirecionado dentro de `%TEMP%`, somente no processo que executa o comando. Nenhum token CLI foi vinculado ao projeto e nenhuma configuração global do usuário foi alterada.
- O `.env.local` ignorado pelo Git contém apenas URL DEV e chave publishable. `.env.example` documenta `PIER360_APP_URL` e `SUPABASE_SECRET_KEY` como placeholders; nenhuma chave privilegiada real está no repositório ou no browser.
- `database.types.ts` está sincronizado com o schema remoto DEV, incluindo as rotinas de ativação e gestão de acesso; regenerar após cada migration que alterar o contrato.
- O login server-side e as rotas AAL2 já compilam. No DEV, o Turnstile tem secret no Supabase Auth, site key no Vercel Preview e hostname Preview permitido no widget Cloudflare; o widget foi validado visualmente na tela de login. Não enviar convite real até conferir o destinatário e o redirect efetivo para o Preview.
- Vercel está vinculado ao repositório; Preview e callback estão configurados para `preview-v1`. A área administrativa requer `PIER360_APP_URL` e `SUPABASE_SECRET_KEY` como variáveis server-side; a chave privilegiada não está configurada no Preview.
- Não há tenant, usuário Auth ou Super Admin bootstrap no banco. O primeiro usuário e a capability global precisam ser provisionados por operação controlada depois de definido o e-mail corporativo.
- Turnstile está habilitado no Supabase Auth; a chave secreta permanece no Supabase. A site key e hostname Preview estão configurados e o widget responde “Sucesso!”. A validação de um fluxo de Auth completo ainda depende do bootstrap da primeira identidade.

Antes da integração, provisionar ou conectar um projeto Supabase de desenvolvimento. Se for um projeto Free novo e os e-mails Auth precisarem de identidade visual, reservar SMTP próprio: a partir de 3 de junho de 2026, novos projetos Free usando o SMTP padrão não podem customizar templates de e-mail. Além disso, novos projetos podem não expor tabelas `public` automaticamente na Data API; planejar grants explícitos junto com RLS.

## Referências oficiais consultadas

- [Supabase CAPTCHA no Auth](https://supabase.com/docs/guides/auth/auth-captcha)
- [Supabase MFA no Auth](https://supabase.com/docs/guides/auth/auth-mfa)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Alteração de templates de e-mail no plano Free](https://supabase.com/changelog/46599-changes-to-email-template-customisation-on-free-tier)
- [Exposição explícita de tabelas à Data API](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)
