-- Add tenant memberships without replacing existing memberships or grants.
-- Every change runs under the authenticated Super Admin and is captured by
-- the existing audit triggers on profiles, memberships, and module grants.

create or replace function public.pier360_grant_member_tenants(
  target_user_id uuid,
  target_tenant_ids uuid[],
  target_membership_role text,
  target_module_keys text[],
  target_module_capability text default 'read',
  target_full_name text default null
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_actor_id uuid := auth.uid();
  profile_status text;
  membership_status text;
begin
  if current_actor_id is null or not public.pier360_is_super_admin() then
    raise exception 'super_admin_required' using errcode = '42501';
  end if;

  if target_user_id is null
    or target_tenant_ids is null
    or array_ndims(target_tenant_ids) is distinct from 1
    or cardinality(target_tenant_ids) not between 1 and 100
    or target_membership_role is null
    or target_membership_role not in ('tenant_admin', 'analyst', 'reader')
    or target_module_capability is null
    or target_module_capability not in ('read', 'manage')
    or target_module_keys is null
    or cardinality(target_module_keys) > 3
    or exists (
      select 1 from unnest(target_tenant_ids) as requested(tenant_id)
      where tenant_id is null
    )
    or exists (
      select 1 from unnest(target_module_keys) as requested(module_key)
      where module_key is null
         or module_key not in ('dashboard', 'assets', 'vulnerabilities')
    ) then
    raise exception 'invalid_member_access' using errcode = '22023';
  end if;

  if cardinality(target_tenant_ids) <> (
    select count(distinct tenant_id)
    from unnest(target_tenant_ids) as requested(tenant_id)
  ) or cardinality(target_module_keys) <> (
    select count(distinct module_key)
    from unnest(target_module_keys) as requested(module_key)
  ) then
    raise exception 'duplicate_member_access' using errcode = '22023';
  end if;

  if (
    select count(*)
    from public.tenants as tenant
    where tenant.id = any(target_tenant_ids)
      and tenant.status = 'active'
  ) <> cardinality(target_tenant_ids) then
    raise exception 'active_tenant_required' using errcode = '22023';
  end if;

  if not exists (select 1 from auth.users where id = target_user_id) then
    raise exception 'auth_user_required' using errcode = '22023';
  end if;

  select profile.status into profile_status
  from public.profiles as profile
  where profile.id = target_user_id;

  if not found then
    if target_full_name is null or length(btrim(target_full_name)) not between 1 and 160 then
      raise exception 'invalid_full_name' using errcode = '22023';
    end if;

    insert into public.profiles (id, full_name, status)
    values (target_user_id, btrim(target_full_name), 'invited');
    profile_status := 'invited';
  elsif target_full_name is not null then
    if length(btrim(target_full_name)) not between 1 and 160 then
      raise exception 'invalid_full_name' using errcode = '22023';
    end if;

    update public.profiles
    set full_name = btrim(target_full_name), updated_at = now()
    where id = target_user_id;
  end if;

  if profile_status = 'active' then
    membership_status := 'active';
  elsif profile_status = 'invited' then
    membership_status := 'invited';
  else
    raise exception 'active_profile_required' using errcode = '22023';
  end if;

  with inserted_memberships as (
    insert into public.tenant_memberships (
      tenant_id, user_id, role, status, invited_by
    )
    select requested.tenant_id, target_user_id, target_membership_role,
           membership_status, current_actor_id
    from unnest(target_tenant_ids) as requested(tenant_id)
    on conflict (tenant_id, user_id) do nothing
    returning tenant_id
  )
  insert into public.user_module_permissions (
    tenant_id, user_id, module_key, capability, granted_by
  )
  select inserted.tenant_id, target_user_id, requested.module_key,
         target_module_capability, current_actor_id
  from inserted_memberships as inserted
  cross join unnest(target_module_keys) as requested(module_key)
  on conflict (tenant_id, user_id, module_key, capability) do nothing;
end;
$$;

revoke all on function public.pier360_grant_member_tenants(uuid, uuid[], text, text[], text, text)
  from public, anon;
grant execute on function public.pier360_grant_member_tenants(uuid, uuid[], text, text[], text, text)
  to authenticated;

