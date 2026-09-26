-- Fold pre-MFA invite activation into the existing access policies, avoiding
-- duplicate permissive RLS paths while preserving the super-admin controls.

drop policy profiles_select_self_or_super_admin on public.profiles;
drop policy profiles_select_own_pending_activation on public.profiles;
drop policy profiles_update_super_admin on public.profiles;
drop policy profiles_activate_own_invite on public.profiles;

create policy profiles_select_self_pending_or_super_admin
  on public.profiles for select to authenticated
  using (
    (
      (select auth.uid()) = id
      and ((select public.pier360_is_aal2()) or status = 'invited')
    )
    or (select public.pier360_is_super_admin())
  );
create policy profiles_update_super_admin_or_self_activation
  on public.profiles for update to authenticated
  using (
    (select public.pier360_is_super_admin())
    or ((select auth.uid()) = id and status = 'invited')
  )
  with check (
    (select public.pier360_is_super_admin())
    or ((select auth.uid()) = id and status = 'active')
  );

drop policy tenant_memberships_select_self_or_super_admin on public.tenant_memberships;
drop policy memberships_select_own_pending_activation on public.tenant_memberships;
drop policy tenant_memberships_update_super_admin on public.tenant_memberships;
drop policy memberships_activate_own_invite on public.tenant_memberships;

create policy tenant_memberships_select_self_pending_or_super_admin
  on public.tenant_memberships for select to authenticated
  using (
    (
      (select auth.uid()) = user_id
      and ((select public.pier360_is_aal2()) or status = 'invited')
    )
    or (select public.pier360_is_super_admin())
  );
create policy tenant_memberships_update_super_admin_or_self_activation
  on public.tenant_memberships for update to authenticated
  using (
    (select public.pier360_is_super_admin())
    or ((select auth.uid()) = user_id and status = 'invited')
  )
  with check (
    (select public.pier360_is_super_admin())
    or ((select auth.uid()) = user_id and status = 'active')
  );
