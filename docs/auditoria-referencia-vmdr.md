# Auditoria da plataforma de referência e decisões para o PUS

Data da auditoria: 25/09/2026. Leitura somente das páginas abertas no Chrome; nenhum dado foi alterado.

## O que foi observado

O VMDR — PierSec Exposure Hub apresenta navegação por Dashboard, Vulnerabilidades, Ativos, Hardening, Integrações e Configurações, com seleção de tenant. A referência é útil para fluxos e hierarquia de informação, mas PIER360 deve ter linguagem visual, estrutura e componentes próprios.

| Área | Padrões observados que ajudam a especificar a V1 |
|---|---|
| Dashboard | Resumo de exposição, severidade, idade das vulnerabilidades, KEV/EPSS, sistemas operacionais e ativos prioritários. |
| Ativos | Busca por hostname/IP, filtros por status/severidade/tempo, ordenação, hostname, IP, vulnerabilidades e última atualização. A ficha inclui identificador do agente, IP, último contato observado e vulnerabilidades associadas. |
| Vulnerabilidades | Busca por título/CVE/host, filtros por severidade, status, último visto e primeira detecção; lista no grão de vulnerabilidade por host, com CVE, pacote, ameaça, agente, severidade e idade. |
| Detalhe de vulnerabilidade | CVSS, EPSS/KEV, orientação de correção, versão observada, hosts afetados e tratamento por host; há estados de tratamento, responsável implícito e comentários. |
| Admin nas imagens | Tabela de usuários por nome/e-mail/role/tenant/status e edição de módulos visíveis em uma tela específica de super admin. As imagens são referências de interação, não especificação literal de layout ou cores. |
| Áreas posteriores | Hardening, integrações e CTI aparecem no material de referência, mas ficam fora da V1.0, exceto pelos dados mínimos necessários ao contexto de vulnerabilidade. |

## Validações e riscos encontrados

- Em um carregamento, os cards de vulnerabilidade começaram indisponíveis e depois exibiram valores; na tela de vulnerabilidades, havia dados na tabela enquanto alguns totais continuavam indisponíveis. Para o PUS, diferenciar carregando, zero confirmado, dado ausente e falha/atraso do Wazuh.
- Ao navegar da ficha de vulnerabilidade para Hardening e Configurações, o conteúdo e o item ativo da navegação mudaram, mas a URL manteve o endereço da ficha de vulnerabilidade. Validar URL, recarregamento, botão voltar e links diretos na aplicação nova.
- O status “Ativo” mostrado para ativos na referência não cobre os três grupos pedidos para agentes Wazuh. A V1 deve usar a semântica original `active`, `disconnected`, `pending` e agrupar `never_connected` dentro de Pendente sem apagar a origem.
- A ficha de ativo mostra “último visto”, que não é automaticamente a mesma coisa que último scan. Separar `lastKeepAlive` (contato), `scan.time`/`scan_time` (inventário Syscollector), `vulnerability.detected_at` (detecção do finding) e horário da consulta do PUS.
- Métricas e registros observados pertencem à instância de demonstração/referência; não são números de aceite nem devem ser copiados para dados de produção.

## Direção visual

Criar sistema de design próprio com base nas preferências explícitas: interface intuitiva, imersiva, modo claro e escuro e cores agradáveis. A referência usa fundo roxo muito escuro, superfície violeta, acento roxo e indicadores de severidade coloridos. PIER360 pode aproveitar a hierarquia (título, filtros, cards, tabela, detalhe) e construir sua própria paleta, ícones, tipografia e navegação. As cores de severidade devem manter contraste e sempre vir acompanhadas por texto/ícone.

## Fontes técnicas Wazuh

O PDF de integração Manager API/VMDR enviado pelo usuário orienta a busca de status/agentes e inventário Syscollector. Para o scan do inventário de pacotes, ele nomeia o campo `scan_time`; os exemplos atuais da documentação oficial mostram o mesmo significado em `scan.time`. O adaptador deve confirmar e normalizar a forma realmente retornada pela versão instalada. O PDF é referência técnica e não amplia, por si só, o escopo visual da V1 (por exemplo, não cria uma tela de inventário de pacotes).

As vulnerabilidades serão consultadas em tempo real de leitura do índice States pelo backend, conforme decisão explícita do usuário; o índice continua refletindo as cadências de coleta e indexação do Wazuh. Os contratos, campos e links oficiais consultados estão reunidos na skill local [Wazuh PUS Integration](../.agents/skills/wazuh-pus-integration/SKILL.md) e em sua [referência de dados](../.agents/skills/wazuh-pus-integration/references/wazuh-data-contracts.md).
