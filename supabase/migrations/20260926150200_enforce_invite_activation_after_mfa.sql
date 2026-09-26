-- Prevent invitees from activating profile and tenant access before MFA is verified.

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

  if not public.pier360_is_aal2() then
    raise exception 'mfa_required' using errcode = '42501';
  end if;

  update public.profiles
  set status = 'active'
  where id = current_user_id and status = 'invited';
  get diagnostics activated_count = row_count;

  update public.tenant_memberships
  set status = 'active'
  where user_id = current_user_id and status = 'invited';
  get diagnostics activated_membership_count = row_count;

  return activated_count + activated_membership_count > 0;
end;
$$;

drop policy profiles_update_super_admin_or_self_activation on public.profiles;
create policy profiles_update_super_admin_or_self_activation
  on public.profiles for update to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (
      (select auth.uid()) = id
      and status = 'invited'
      and (select public.pier360_is_aal2())
    )
  )
  with check (
    (select public.pier360_is_super_admin())
    or (
      (select auth.uid()) = id
      and status = 'active'
      and (select public.pier360_is_aal2())
    )
  );

drop policy tenant_memberships_update_super_admin_or_self_activation on public.tenant_memberships;
create policy tenant_memberships_update_super_admin_or_self_activation
  on public.tenant_memberships for update to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (
      (select auth.uid()) = user_id
      and status = 'invited'
      and (select public.pier360_is_aal2())
    )
  )
  with check (
    (select public.pier360_is_super_admin())
    or (
      (select auth.uid()) = user_id
      and status = 'active'
      and (select public.pier360_is_aal2())
    )
  );
