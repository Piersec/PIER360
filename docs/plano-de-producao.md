# Plano de produção — PUS PIER360 V1.0

## Decisão de plano antes do go-live

Usar Vercel Hobby e Supabase Free para protótipo/validação inicial, sem tratar esse arranjo como ambiente de produção de segurança. Em 25/09/2026, a Vercel limita o Hobby a uso pessoal e não comercial; para uma plataforma PIER360 de negócio, planejar Vercel Pro ou outro plano explicitamente autorizado para uso comercial. O Hobby agenda Cron no máximo uma vez por dia, então não serve para sincronização frequente de agentes.

O Supabase Free pode pausar projetos com pouca atividade em janela de sete dias, possui cotas menores e não deve ser presumido como banco de produção com recuperação/SLA adequados. Confirmar limites atuais; dimensionar o plano pago, região, retenção, backups e suporte para dados de segurança antes de produção. A arquitetura acima usa conector próprio para não depender de Vercel Cron gratuito.

Fontes atuais: [política do Hobby Vercel](https://vercel.com/docs/plans/hobby), [limites de Cron Vercel](https://vercel.com/docs/cron-jobs/usage-and-pricing), [preços Supabase](https://supabase.com/pricing), [pausa Free Supabase](https://supabase.com/docs/guides/platform/free-project-pausing).

## Caminho de implantação

### 1. Preparar contas e ambientes

- Criar projetos e domínio separados para dev, staging e produção; acesso por grupo nominal e MFA nas contas administrativas dos provedores.
- Selecionar região próxima da maioria dos usuários/Wazuh e aprovada para requisitos organizacionais de residência/privacidade.
- Definir domínio próprio, DNS, TLS e proxy Cloudflare. Ativar WAF/rate limiting conforme recursos incluídos no plano e testar o caminho Cloudflare -> Vercel.
- Produção Supabase em plano adequado com limites observados, retenção/logs e política de backup; confirmar se exigências empresariais de SSO, auditoria e suporte pedem outro tier.

### 2. Preparar conectividade Wazuh

- Validar Manager API, Indexer API, versão, certificados e origem/rede de cada tenant em ambiente de teste.
- Criar contas/roles de leitura separadas para Manager e Indexer; limitar índice e campos necessários. Proibir rotas de escrita/remediação na aplicação V1.
- Instalar o gateway de leitura dentro da rede controlada; permitir acesso do BFF por rede privada ou Cloudflare Tunnel/Access com autenticação de serviço. Credenciais Wazuh ficam no secret store do gateway, com rotação. Não expor 55000/9200 nem colocar credenciais Wazuh em variáveis de cliente.
- Restringir o gateway a operações tipadas somente leitura e aos padrões de índice/campos necessários. Validar TLS upstream; bloquear URL/DSL/índice arbitrários. Aplicar autenticação forte, rate limit, timeout, circuit breaker e tenant/conexão resolvidos no backend.
- Configurar um worker/scheduler para egress HTTPS a FIRST EPSS e CISA KEV e envio autenticado do catálogo normalizado ao backend PUS. O worker não depende de Vercel Cron Hobby: EPSS uma vez ao dia após a publicação; KEV a cada 6 horas. Revisar a cadência com a publicação real das fontes e o limite operacional.

### 3. Segurança e banco

- Revisar todas as migrations, constraints, índices e policies RLS com teste cruzado entre tenants e permissões.
- Desabilitar cadastro público; configurar templates e domínio de redirecionamento de convite/recuperação; restringir função de convite ao super admin.
- Configurar Turnstile no Auth (login/cadastro/recuperação necessários) e confirmar validação server-side. Turnstile não validado não protege formulário.
- Tornar MFA TOTP obrigatório e verificar AAL2 em cada rota de servidor e policy necessária. Criar rotina segura de recuperação de acesso.
- Separar publishable key do browser de service/secret keys; verificar que chaves administrativas nunca aparecem em bundle, logs, sourcemaps, browser storage ou responses.
- Configurar sessão segura, CORS, CSP, cookies, headers, rate limits, dependabot/alertas de dependências e logging/auditoria sem secrets.

### 4. Dados e operação

- Rodar migrações compatíveis e reversíveis, com backup/snapshot anterior e estratégia de rollback. Executar restore em staging e medir recuperação.
- Executar leituras de validação ao vivo na Manager API e Indexer API; verificar status de agents, timestamps Syscollector e contagens por severidade antes de abrir acesso aos usuários.
- Verificar horário/resultado da última consulta, latência p95, timeout, resposta parcial/shards, falhas por origem e quantidade lida. Alertar sobre falhas repetidas/Indexer indisponível; a UI deve deixar dados indisponíveis, não reaproveitar dado antigo silenciosamente nem exibir zero.
- Verificar a execução independente de EPSS/KEV, data dos dados aplicados, volume de CVEs cruzadas, idempotência, retries e alerta de fonte desatualizada. Falha deve preservar o último enrichment válido e expor sua data.
- Definir retenção de `source_query_runs`, audit log e comentários; executar processo para desativar usuário/tenant sem apagar indevidamente histórico operacional.
- Documentar operação: indisponibilidade Wazuh, credencial expirada, pausa/limite de banco, restauração, rotação de secret, tenant bloqueado e rollback.

### 5. Piloto e liberação

1. Publicar release candidate em staging; completar todos os itens bloqueantes do [plano de testes](./plano-de-testes.md).
2. Fazer UAT com usuários representativos e dados sanitizados; resolver divergências com o Wazuh owner.
3. Piloto com um tenant e número limitado de usuários; acompanhar erros, horário das consultas ao vivo, latência/carga Indexer, custo e feedback por janela operacional acordada.
4. Promover a mesma build/migrations aprovadas; ativar módulos somente para usuários autorizados; confirmar URL, certificados, DNS e MFA em produção.
5. Acompanhar telemetria nas primeiras 24–72 horas, fazer reconciliação com Manager/Indexer e manter rollback da aplicação e plano de migração compatível.
6. Expandir tenants gradualmente após aceite do piloto e confirmação de capacidade/custo.

## Go/no-go

- **Go:** tenant isolation e RLS aprovados; MFA/Turnstile verificados; secrets só server-side; gateway limitado a leitura; consultas ao vivo com horário/estado visíveis; jobs EPSS/KEV com freshness/alertas aprovados; totais reconciliados; backup/restore do banco/workflows/enrichments provado; observabilidade e runbook ativos; limites/plano comercial de hospedagem confirmados.
- **No-go:** Vercel Hobby em uso comercial não autorizado; Supabase Free aceito como produção sem decisão de continuidade e restore; Manager/Indexer expostos publicamente; RLS ausente em qualquer tabela multi-tenant; falha/parcial do Indexer mostrada como zero/resolvido; EPSS/KEV ausente ou desatualizado apresentado como dado atual; função administrativa acessível sem MFA/role; nenhum procedimento de recuperação.

## Operação contínua

- Rever contas super admin e grants em cadência definida; remover acesso de saída; auditar mudanças de tenancy e capabilities.
- Atualizar dependências e versões do Wazuh em staging antes da produção; comparar schemas e permissões quando o Wazuh atualizar.
- Reavaliar plano de custos/uso Supabase/Vercel, retenção e capacidade quando tenants, agents ou findings crescerem.
- Abrir módulos de alertas, Hardening e CTI apenas em releases separadas, cada uma com threat/permission model, contrato de dados e critérios de aceite próprios.
