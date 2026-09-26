# Auditoria do protótipo PIER360

**Data:** 25/09/2026  
**Escopo:** telas locais de demonstração, ligações entre telas e adaptador de dados sintéticos. Esta auditoria não certifica segurança, produção nem integração com serviços externos.

## Resultado executivo

**Pode avançar para a fundação integrada da V1** — backend, autenticação, tenancy e controles de acesso. O protótipo demonstra os fluxos principais e a regra KEV/EPSS compartilhada. **Ainda não pode ser tratado como V1 conectada nem como candidato a produção:** Wazuh, Supabase, autenticação real, autorização server-side e enriquecimentos EPSS/KEV não estão ligados.

## Vistoria por tela

| Tela | Resultado observado | Limite atual |
|---|---|---|
| Visão geral | Severidades, três indicadores KEV/EPSS, regra por tenant, ordem da fila e tabela de ativos renderizam. O atalho combinado abriu 7 vulnerabilidades correspondentes. A fila cabe no cartão sem rolagem horizontal. | Valores e tendência são sintéticos. O seletor de período é demonstrativo. |
| Ativos | Total fecha em 12 = 8 ativos + 2 desconectados + 2 pendentes. Lista, filtros, últimos contato/scan e ficha renderizam; a classificação crítica é binária e aparece como contexto. | Registros são fixtures; somente o tenant PierSec tem ativos de demonstração. Paginação é visual. |
| Vulnerabilidades | Lista, faixas descritivas, filtros, severidade, KEV, workflow e detalhe do finding renderizam. Os filtros do adaptador usam a mesma classificação exibida no dashboard. | Dados EPSS/KEV são sintéticos; alterações de workflow/comentários são locais ao navegador. Paginação é visual. |
| Administração | Formulário de limiar por tenant, lista de usuários, módulos e formulário de edição estão presentes. Foi corrigida a mensagem de edição e a seleção do tenant ao editar um usuário. | Convites, papéis, módulos e fórmulas não têm enforcement no servidor; a configuração é salva no navegador. |

## Verificações executadas

- Verificação sintática com `node --check` em `app.js` e `demo-data.js`.
- Smoke check isolado do adaptador: contagens KEV/EPSS, interseção, cortes, filtros, isolamento de limiar entre tenants, ausência de findings em tenant sem fixture e classificação crítica sem alteração da métrica KEV.
- Vistoria visual e leitura da árvore de acessibilidade no navegador em desktop: dashboard, ativos, ficha do agente, vulnerabilidades, detalhe do finding, administração e formulário de edição.
- Não existe suíte automatizada do projeto. Não foram feitos testes de carga, segurança, mobile, leitor de tela nem integração externa nesta etapa.

## Pendências para avançar

1. Implementar API/BFF server-side; não chamar Manager/Indexer do browser nem aceitar índices, DSL ou URLs definidos pelo cliente.
2. Integrar Manager API para agentes e Syscollector; confirmar versão, paginação, `lastKeepAlive` e `scan.time`/`scan_time` em ambiente não produtivo.
3. Integrar leitura autorizada do índice States no Indexer, com paginação, horário/resultado da consulta e estado explícito para erro, timeout ou resultado parcial.
4. Implementar Supabase Auth, MFA/Turnstile, autorização de rota/API, RLS, grants por módulo/tenant, trilha de auditoria e persistência server-side do workflow, criticidade e limiar.
5. Implementar enriquecimento EPSS/KEV por CVE, mantendo fonte, data e frescor; ausência/falha não pode virar zero ou KEV falso.
6. Transformar paginação e período em controles funcionais e implementar estados de carregamento, indisponibilidade e resultado parcial antes do UAT.
7. Após os dados reais estabilizarem, realizar a fase UI/UX: testes com analistas/gestores, responsividade, leitura da fila, foco/teclado, contraste, leitor de tela e revisão de textos; corrigir antes do UAT.
8. Executar regressão funcional, teste cruzado de tenant/módulo, reconciliação com Wazuh, backup/restore e piloto conforme [plano de testes](./plano-de-testes.md) e [plano de produção](./plano-de-producao.md).

O próximo marco recomendado é o **Gate A da plataforma**: aprovar fórmula, rótulos e escopo desta demonstração; em seguida iniciar backend/Auth/tenancy. A integração Wazuh começa após os controles de acesso e o contrato server-side estarem prontos.
