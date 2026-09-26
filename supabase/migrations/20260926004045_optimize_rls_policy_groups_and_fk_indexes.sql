-- Keep read policies separate from write policies to avoid overlapping permissive SELECT paths.
drop policy tenants_manage_super_admin on public.tenants;
create policy tenants_insert_super_admin
  on public.tenants for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy tenants_update_super_admin
  on public.tenants for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy tenants_delete_super_admin
  on public.tenants for delete to authenticated
  using ((select public.pier360_is_super_admin()));

drop policy profiles_manage_super_admin on public.profiles;
create policy profiles_insert_super_admin
  on public.profiles for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy profiles_update_super_admin
  on public.profiles for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy profiles_delete_super_admin
  on public.profiles for delete to authenticated
  using ((select public.pier360_is_super_admin()));

drop policy tenant_memberships_manage_super_admin on public.tenant_memberships;
create policy tenant_memberships_insert_super_admin
  on public.tenant_memberships for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy tenant_memberships_update_super_admin
  on public.tenant_memberships for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy tenant_memberships_delete_super_admin
  on public.tenant_memberships for delete to authenticated
  using ((select public.pier360_is_super_admin()));

drop policy user_module_permissions_manage_super_admin on public.user_module_permissions;
create policy user_module_permissions_insert_super_admin
  on public.user_module_permissions for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy user_module_permissions_update_super_admin
  on public.user_module_permissions for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy user_module_permissions_delete_super_admin
  on public.user_module_permissions for delete to authenticated
  using ((select public.pier360_is_super_admin()));

drop policy wazuh_connections_manage_super_admin on public.wazuh_connections;
create policy wazuh_connections_insert_super_admin
  on public.wazuh_connections for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy wazuh_connections_update_super_admin
  on public.wazuh_connections for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy wazuh_connections_delete_super_admin
  on public.wazuh_connections for delete to authenticated
  using ((select public.pier360_is_super_admin()));

drop policy asset_classifications_manage_assets_module on public.asset_classifications;
create policy asset_classifications_insert_assets_module
  on public.asset_classifications for insert to authenticated
  with check (
    (select public.pier360_is_super_admin())
    or (
      (select public.pier360_has_tenant_module(tenant_id, 'assets', 'manage'))
      and (created_by is null or created_by = (select auth.uid()))
      and (updated_by is null or updated_by = (select auth.uid()))
    )
  );
create policy asset_classifications_update_assets_module
  on public.asset_classifications for update to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'assets', 'manage'))
  )
  with check (
    (select public.pier360_is_super_admin())
    or (
      (select public.pier360_has_tenant_module(tenant_id, 'assets', 'manage'))
      and (created_by is null or created_by = (select auth.uid()))
      and (updated_by is null or updated_by = (select auth.uid()))
    )
  );
create policy asset_classifications_delete_assets_module
  on public.asset_classifications for delete to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'assets', 'manage'))
  );

drop policy priority_configs_manage_super_admin on public.tenant_vulnerability_priority_configs;
create policy priority_configs_insert_super_admin
  on public.tenant_vulnerability_priority_configs for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy priority_configs_update_super_admin
  on public.tenant_vulnerability_priority_configs for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy priority_configs_delete_super_admin
  on public.tenant_vulnerability_priority_configs for delete to authenticated
  using ((select public.pier360_is_super_admin()));

drop policy vulnerability_work_items_manage_module on public.vulnerability_work_items;
create policy vulnerability_work_items_insert_module
  on public.vulnerability_work_items for insert to authenticated
  with check (
    (select public.pier360_is_super_admin())
    or (
      (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'manage'))
      and (created_by is null or created_by = (select auth.uid()))
      and (updated_by is null or updated_by = (select auth.uid()))
    )
  );
create policy vulnerability_work_items_update_module
  on public.vulnerability_work_items for update to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'manage'))
  )
  with check (
    (select public.pier360_is_super_admin())
    or (
      (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'manage'))
      and (created_by is null or created_by = (select auth.uid()))
      and (updated_by is null or updated_by = (select auth.uid()))
    )
  );
create policy vulnerability_work_items_delete_module
  on public.vulnerability_work_items for delete to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'manage'))
  );

-- Index every non-primary foreign key to support joins and parent updates/deletes at scale.
create index if not exists asset_classifications_created_by_idx
  on public.asset_classifications (created_by);
create index if not exists asset_classifications_updated_by_idx
  on public.asset_classifications (updated_by);
create index if not exists global_capabilities_granted_by_idx
  on public.global_capabilities (granted_by);
create index if not exists tenant_memberships_invited_by_idx
  on public.tenant_memberships (invited_by);
create index if not exists priority_configs_updated_by_idx
  on public.tenant_vulnerability_priority_configs (updated_by);
create index if not exists user_module_permissions_granted_by_idx
  on public.user_module_permissions (granted_by);
create index if not exists vulnerability_work_items_created_by_idx
  on public.vulnerability_work_items (created_by);
create index if not exists vulnerability_work_items_updated_by_idx
  on public.vulnerability_work_items (updated_by);
create index if not exists vulnerability_work_items_assignee_idx
  on public.vulnerability_work_items (tenant_id, assignee_user_id);
