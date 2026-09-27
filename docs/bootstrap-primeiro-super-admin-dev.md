# Bootstrap inicial do Super Admin — DEV

## Objetivo e limites

Este é um procedimento único para inicializar o primeiro tenant e o primeiro Super Admin no projeto Supabase DEV (`pier360-dev`). A tela de administração não pode executar o primeiro bootstrap porque suas operações exigem uma sessão Super Admin AAL2 já existente.

Este roteiro não altera schema e, portanto, não é uma migration. Ele faz apenas o seed inicial de dados. Execute somente no projeto DEV após conferir o nome do projeto e a organização no Dashboard. Não use em Production e não cole chaves Supabase neste documento, no Git ou na conversa.

## Dados necessários

- E-mail corporativo que será o primeiro Super Admin.
- Nome completo dessa pessoa.
- Nome do tenant DEV e slug em minúsculas, por exemplo `piersec-dev`.
- UUID do usuário Auth depois de criar o convite/conta.

## Antes de convidar

O Supabase Auth DEV usa hoje como `Site URL` o domínio Production. A tela de administração do PIER360 não pode enviar o primeiro convite porque ainda não há Super Admin. Para que o convite inicial termine no fluxo de criação de senha do Preview:

No SQL Editor do projeto DEV, primeiro substitua o slug e confira que não existe outro Super Admin nem tenant com esse slug:

```sql
select
  (select count(*) from public.global_capabilities
   where capability = 'platform.super_admin') as existing_super_admins,
  exists (
    select 1 from public.tenants
    where slug = 'REPLACE_WITH_DEV_TENANT_SLUG'
  ) as tenant_slug_already_exists;
```

O resultado necessário é `existing_super_admins = 0` e `tenant_slug_already_exists = false`. Se não corresponder, pare e não envie convite.

1. No Supabase DEV, abra **Authentication → URL Configuration** e anote o `Site URL` atual.
2. Temporariamente defina o `Site URL` como a callback completa do Preview mostrada abaixo.
3. Em **Authentication → Users → Add user → Send invitation**, confira o e-mail e envie o convite.
4. Restaure o `Site URL` original logo após o envio. A alteração temporária também afeta os outros e-mails Auth gerados durante esse intervalo; não faça outra operação Auth enquanto estiver ativa.

Não execute esses passos antes de confirmar o e-mail do destinatário. O convite envia e-mail real. O destino esperado é:

```text
https://piersec-pier360-git-preview-v1-davidbasile2000-4092s-projects.vercel.app/auth/callback?next=/reset-password
```

O redirect acima já está na allowlist do projeto DEV. O Supabase usa o `Site URL` como destino padrão quando o convite não fornece `redirectTo`; a mudança é somente temporária no projeto DEV. O usuário convidado deve concluir a confirmação e definir a própria senha; não use senha temporária compartilhada.

## Seed inicial pelo SQL Editor

Depois que o convite criar um usuário em **Authentication → Users**, copie o UUID dele. No **SQL Editor** do projeto `pier360-dev`, substitua todos os valores `REPLACE_...` abaixo. Use o mesmo e-mail do convite. O bloco verifica usuário, tenant e ausência de Super Admin anterior; qualquer divergência aborta a transação.

```sql
begin;

do $bootstrap$
declare
  target_user_id uuid := 'REPLACE_WITH_AUTH_USER_UUID'::uuid;
  target_email text := lower(btrim('REPLACE_WITH_CORPORATE_EMAIL'));
  target_full_name text := btrim('REPLACE_WITH_FULL_NAME');
  target_tenant_name text := btrim('REPLACE_WITH_DEV_TENANT_NAME');
  target_tenant_slug text := lower(btrim('REPLACE_WITH_DEV_TENANT_SLUG'));
  actual_auth_email text;
  target_tenant_id uuid;
begin
  if target_user_id is null
    or target_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
    or length(target_email) > 254
    or length(target_full_name) not between 1 and 160
    or length(target_tenant_name) not between 1 and 160
    or target_tenant_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$' then
    raise exception 'bootstrap_input_invalid';
  end if;

  select lower(u.email) into actual_auth_email
  from auth.users as u
  where u.id = target_user_id;

  if actual_auth_email is null or actual_auth_email <> target_email then
    raise exception 'auth_user_id_email_mismatch';
  end if;
  if exists (
    select 1 from public.global_capabilities
    where capability = 'platform.super_admin'
  ) then
    raise exception 'super_admin_already_bootstrapped';
  end if;
  if exists (
    select 1 from public.tenants where slug = target_tenant_slug
  ) then
    raise exception 'tenant_slug_already_exists';
  end if;
  if exists (
    select 1 from public.profiles where id = target_user_id
  ) then
    raise exception 'profile_already_exists';
  end if;

  insert into public.tenants (name, slug, status)
  values (target_tenant_name, target_tenant_slug, 'active')
  returning id into target_tenant_id;

  insert into public.profiles (id, full_name, status)
  values (target_user_id, target_full_name, 'invited');

  insert into public.tenant_memberships (
    tenant_id, user_id, role, status, invited_by
  ) values (
    target_tenant_id, target_user_id, 'tenant_admin', 'invited', null
  );

  insert into public.global_capabilities (user_id, capability, granted_by)
  values (target_user_id, 'platform.super_admin', null);

  raise notice 'Bootstrap inicial criado. Tenant ID: %', target_tenant_id;
end;
$bootstrap$;

commit;
```

Se o bloco falhar, não reenvie o convite. Leia o erro, corrija a causa e reutilize o UUID do mesmo usuário. Em caso de erro, a transação não deve deixar metade do seed aplicado.

As triggers existentes criam as configurações padrão de prioridade e as entradas de auditoria. Como o seed é executado pelo SQL Editor antes de existir uma sessão autenticada da plataforma, as entradas iniciais terão `actor_user_id = NULL`; registre operador e horário no controle de mudança do DEV. As operações posteriores pela plataforma serão auditadas com o ator autenticado.

## Conclusão do acesso

1. A pessoa aceita o convite no link do Preview, define sua própria senha e conclui a confirmação de e-mail.
2. A callback ativa o perfil e o vínculo pendentes. A pessoa entra no PIER360 Preview, cadastra o fator TOTP e confirma-o para atingir AAL2.
3. Confirme `/admin/users` e o evento de auditoria no tenant DEV.
4. Configure `SUPABASE_SECRET_KEY` do projeto DEV em Vercel como **Secret**, somente no ambiente Preview e branch `preview-v1`. Nunca use `NEXT_PUBLIC_`, Config ou a chave de Production. Essa chave é necessária para a listagem e os convites pela tela administrativa.
5. Crie contas de QA e o segundo tenant de teste por procedimento controlado; execute os testes cruzados de leitura/escrita, capabilities e AAL antes de aprovar o Gate 2.8.

## Verificação pós-seed

Substitua `REPLACE_WITH_AUTH_USER_UUID` e execute uma consulta read-only no SQL Editor:

```sql
select
  t.name as tenant_name,
  t.slug as tenant_slug,
  p.full_name,
  p.status as profile_status,
  tm.role,
  tm.status as membership_status,
  gc.capability
from public.tenants as t
join public.tenant_memberships as tm on tm.tenant_id = t.id
join public.profiles as p on p.id = tm.user_id
join public.global_capabilities as gc on gc.user_id = tm.user_id
where tm.user_id = 'REPLACE_WITH_AUTH_USER_UUID'::uuid
  and gc.capability = 'platform.super_admin';
```

Esperado antes de aceitar o convite: uma linha para o tenant escolhido, perfil/vínculo `invited` e capability `platform.super_admin`. Depois da callback de confirmação, perfil e vínculo devem estar `active`.

## Referências

- [Supabase Auth: Users e convites](https://supabase.com/docs/guides/auth/users)
- [Supabase JavaScript: `inviteUserByEmail`](https://supabase.com/docs/reference/javascript/auth-admin-inviteuserbyemail)
- [Supabase Auth: MFA](https://supabase.com/docs/guides/auth/auth-mfa)
