-- Convert administrative routines to invoker rights and permit only a
-- one-way, self-scoped invite activation before the user enrolls in MFA.

drop function if exists public.pier360_guard_self_invite_activation();

create or replace function public.pier360_guard_self_invite_activation()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if auth.uid() is null or public.pier360_is_super_admin() then
    return new;
  end if;

  if tg_table_name = 'profiles' and old.id = (select auth.uid()) then
    if old.status <> 'invited'
      or new.status <> 'active'
      or new.id is distinct from old.id
      or new.full_name is distinct from old.full_name then
      raise exception 'only_invite_activation_is_allowed' using errcode = '42501';
    end if;
  elsif tg_table_name = 'tenant_memberships' and old.user_id = (select auth.uid()) then
    if old.status <> 'invited'
      or new.status <> 'active'
      or new.tenant_id is distinct from old.tenant_id
      or new.user_id is distinct from old.user_id
      or new.role is distinct from old.role
      or new.invited_by is distinct from old.invited_by then
      raise exception 'only_invite_activation_is_allowed' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

create trigger profiles_guard_self_invite_activation
  before update on public.profiles
  for each row execute function public.pier360_guard_self_invite_activation();
create trigger memberships_guard_self_invite_activation
  before update on public.tenant_memberships
  for each row execute function public.pier360_guard_self_invite_activation();

create policy profiles_select_own_pending_activation
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id and status = 'invited');
create policy profiles_activate_own_invite
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id and status = 'invited')
  with check ((select auth.uid()) = id and status = 'active');

create policy memberships_select_own_pending_activation
  on public.tenant_memberships for select to authenticated
  using ((select auth.uid()) = user_id and status = 'invited');
create policy memberships_activate_own_invite
  on public.tenant_memberships for update to authenticated
  using ((select auth.uid()) = user_id and status = 'invited')
  with check ((select auth.uid()) = user_id and status = 'active');

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
security invoker
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
security invoker
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
security invoker
set search_path = ''
as $$
declare
  current_user_id uuid := auth.uid();
  activated_count integer := 0;
  activated_membership_count integer := 0;
begin
  if current_user_id is null then
    raise exception 'authentication_required' using errcode = '42501';
  end if;

  update public.profiles
  set status = 'active'
  where id = current_user_id and status = 'invited';
  get diagnostics activated_count = row_count;

  update public.tenant_memberships
  set status = 'active'
  where user_id = current_user_id and status = 'invited';
  get diagnostics activated_membership_count = row_count;
  activated_count := activated_count + activated_membership_count;

  return activated_count > 0;
end;
$$;

revoke all on function public.pier360_guard_self_invite_activation() from public, anon, authenticated;
revoke all on function public.pier360_provision_tenant_member(uuid, uuid, text, text, text[], text)
  from public, anon;
revoke all on function public.pier360_update_tenant_member_access(uuid, uuid, text, text, text, text[], text)
  from public, anon;
revoke all on function public.pier360_activate_current_memberships() from public, anon;
grant execute on function public.pier360_provision_tenant_member(uuid, uuid, text, text, text[], text)
  to authenticated;
grant execute on function public.pier360_update_tenant_member_access(uuid, uuid, text, text, text, text[], text)
  to authenticated;
grant execute on function public.pier360_activate_current_memberships() to authenticated;

grant insert, update, delete on table public.profiles to authenticated;
