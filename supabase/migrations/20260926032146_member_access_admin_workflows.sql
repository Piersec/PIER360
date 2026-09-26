-- Invited member lifecycle and tenant module access administration.
-- Every privileged operation checks the actor in the database and is audited
-- by the existing table triggers.

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

create or replace function public.pier360_provision_tenant_member(
  target_user_id uuid,
  target_tenant_id uuid,
  target_full_name text,
  target_membership_role text,
  target_module_keys text[],
  target_module_capability text default 'read'
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.pier360_is_super_admin() then
    raise exception 'super_admin_required' using errcode = '42501';
  end if;
  if target_user_id is null
    or target_tenant_id is null
    or target_membership_role is null
    or target_membership_role not in ('tenant_admin', 'analyst', 'reader')
    or target_module_capability is null
    or target_module_capability not in ('read', 'manage')
    or target_full_name is null
    or length(btrim(target_full_name)) not between 1 and 160
    or target_module_keys is null
    or cardinality(target_module_keys) > 3
    or exists (
      select 1 from unnest(target_module_keys) as modules(module_key)
      where module_key is null
         or module_key not in ('dashboard', 'assets', 'vulnerabilities')
    ) then
    raise exception 'invalid_member_access' using errcode = '22023';
  end if;
  if (select count(*) from unnest(target_module_keys)) <>
     (select count(distinct module_key) from unnest(target_module_keys) as modules(module_key)) then
    raise exception 'duplicate_module_access' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.tenants
    where id = target_tenant_id and status = 'active'
  ) then
    raise exception 'active_tenant_required' using errcode = '22023';
  end if;
  if not exists (select 1 from auth.users where id = target_user_id) then
    raise exception 'auth_user_required' using errcode = '22023';
  end if;

  insert into public.profiles (id, full_name, status)
  values (target_user_id, btrim(target_full_name), 'invited')
  on conflict (id) do update
    set full_name = excluded.full_name;

  insert into public.tenant_memberships (tenant_id, user_id, role, status, invited_by)
  values (target_tenant_id, target_user_id, target_membership_role, 'invited', auth.uid())
  on conflict (tenant_id, user_id) do update
    set role = excluded.role,
        status = 'invited',
        invited_by = excluded.invited_by;

  delete from public.user_module_permissions
  where tenant_id = target_tenant_id and user_id = target_user_id;

  insert into public.user_module_permissions (
    tenant_id, user_id, module_key, capability, granted_by
  )
  select target_tenant_id, target_user_id, module_key, target_module_capability, auth.uid()
  from unnest(target_module_keys) as modules(module_key);
end;
$$;

create or replace function public.pier360_update_tenant_member_access(
  target_user_id uuid,
  target_tenant_id uuid,
  target_full_name text,
  target_membership_role text,
  target_membership_status text,
  target_module_keys text[],
  target_module_capability text default 'read'
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.pier360_is_super_admin() then
    raise exception 'super_admin_required' using errcode = '42501';
  end if;
  if target_user_id is null
    or target_tenant_id is null
    or target_membership_role is null
    or target_membership_role not in ('tenant_admin', 'analyst', 'reader')
    or target_membership_status is null
    or target_membership_status not in ('invited', 'active', 'disabled')
    or target_module_capability is null
    or target_module_capability not in ('read', 'manage')
    or target_full_name is null
    or length(btrim(target_full_name)) not between 1 and 160
    or target_module_keys is null
    or cardinality(target_module_keys) > 3
    or exists (
      select 1 from unnest(target_module_keys) as modules(module_key)
      where module_key is null
         or module_key not in ('dashboard', 'assets', 'vulnerabilities')
    ) then
    raise exception 'invalid_member_access' using errcode = '22023';
  end if;
  if (select count(*) from unnest(target_module_keys)) <>
     (select count(distinct module_key) from unnest(target_module_keys) as modules(module_key)) then
    raise exception 'duplicate_module_access' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.tenant_memberships
    where tenant_id = target_tenant_id and user_id = target_user_id
  ) then
    raise exception 'tenant_membership_required' using errcode = '22023';
  end if;
  if target_membership_status = 'active' and not exists (
    select 1 from auth.users
    where id = target_user_id and email_confirmed_at is not null
  ) then
    raise exception 'confirmed_email_required' using errcode = '22023';
  end if;

  update public.profiles
  set full_name = btrim(target_full_name),
      updated_at = now()
  where id = target_user_id;

  update public.tenant_memberships
  set role = target_membership_role,
      status = target_membership_status
  where tenant_id = target_tenant_id and user_id = target_user_id;

  delete from public.user_module_permissions
  where tenant_id = target_tenant_id and user_id = target_user_id;

  insert into public.user_module_permissions (
    tenant_id, user_id, module_key, capability, granted_by
  )
  select target_tenant_id, target_user_id, module_key, target_module_capability, auth.uid()
  from unnest(target_module_keys) as modules(module_key);
end;
$$;

create or replace function public.pier360_activate_current_memberships()
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_user_id uuid := auth.uid();
  was_confirmed boolean;
begin
  if current_user_id is null then
    raise exception 'authentication_required' using errcode = '42501';
  end if;
  select email_confirmed_at is not null into was_confirmed
  from auth.users where id = current_user_id;
  if not coalesce(was_confirmed, false) then
    return false;
  end if;

  update public.profiles
  set status = 'active'
  where id = current_user_id and status = 'invited';
  update public.tenant_memberships
  set status = 'active'
  where user_id = current_user_id and status = 'invited';
  return true;
end;
$$;

revoke all on function public.pier360_provision_tenant_member(uuid, uuid, text, text, text[], text)
  from public, anon;
revoke all on function public.pier360_update_tenant_member_access(uuid, uuid, text, text, text, text[], text)
  from public, anon;
revoke all on function public.pier360_activate_current_memberships()
  from public, anon;
grant execute on function public.pier360_provision_tenant_member(uuid, uuid, text, text, text[], text)
  to authenticated;
grant execute on function public.pier360_update_tenant_member_access(uuid, uuid, text, text, text, text[], text)
  to authenticated;
grant execute on function public.pier360_activate_current_memberships()
  to authenticated;
