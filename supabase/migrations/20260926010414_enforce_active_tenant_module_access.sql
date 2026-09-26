-- Keep tenant suspension effective for every member and module grant.
-- Super-admin access remains separately gated by the global capability.
create or replace function public.pier360_has_tenant_module(
  target_tenant_id uuid,
  target_module_key text,
  required_capability text default 'read'
)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select public.pier360_is_aal2()
    and exists (
      select 1
      from public.user_module_permissions as ump
      join public.tenant_memberships as tm
        on tm.tenant_id = ump.tenant_id
       and tm.user_id = ump.user_id
      join public.tenants as t
        on t.id = ump.tenant_id
       and t.status = 'active'
      where ump.tenant_id = target_tenant_id
        and ump.user_id = (select auth.uid())
        and ump.module_key = target_module_key
        and tm.status = 'active'
        and (
          ump.capability = required_capability
          or (required_capability = 'read' and ump.capability = 'manage')
        )
    );
$$;

revoke all on function public.pier360_has_tenant_module(uuid, text, text) from public, anon;
grant execute on function public.pier360_has_tenant_module(uuid, text, text) to authenticated;
