-- PIER360 V1 foundation: tenant identity, authorization, operational overlays, and audit.
-- Auth remains invite-only. All client-facing access is deny-by-default and requires AAL2.

create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 1 and 160),
  slug text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  status text not null default 'active' check (status in ('active', 'suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text not null default '' check (length(full_name) <= 160),
  status text not null default 'invited' check (status in ('invited', 'active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.tenant_memberships (
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'reader' check (role in ('tenant_admin', 'analyst', 'reader')),
  status text not null default 'invited' check (status in ('invited', 'active', 'disabled')),
  invited_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

create table public.global_capabilities (
  user_id uuid not null references auth.users (id) on delete cascade,
  capability text not null check (capability = 'platform.super_admin'),
  granted_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (user_id, capability)
);

create table public.user_module_permissions (
  tenant_id uuid not null,
  user_id uuid not null,
  module_key text not null check (module_key in ('dashboard', 'assets', 'vulnerabilities')),
  capability text not null check (capability in ('read', 'manage')),
  granted_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id, module_key, capability),
  foreign key (tenant_id, user_id)
    references public.tenant_memberships (tenant_id, user_id) on delete cascade
);

create table public.wazuh_connections (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  connection_key text not null check (length(btrim(connection_key)) between 1 and 100),
  display_name text not null check (length(btrim(display_name)) between 1 and 160),
  status text not null default 'pending' check (status in ('pending', 'active', 'disabled')),
  secret_reference text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, id),
  unique (tenant_id, connection_key)
);

create table public.asset_classifications (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  source_connection_id uuid not null,
  source_agent_id text not null check (length(btrim(source_agent_id)) between 1 and 128),
  is_critical boolean not null default false,
  created_by uuid references auth.users (id) on delete set null,
  updated_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, source_connection_id, source_agent_id),
  foreign key (tenant_id, source_connection_id)
    references public.wazuh_connections (tenant_id, id) on delete cascade
);

create table public.tenant_vulnerability_priority_configs (
  tenant_id uuid primary key references public.tenants (id) on delete cascade,
  epss_threshold numeric(5, 4) not null default 0.0880
    check (epss_threshold >= 0 and epss_threshold <= 1),
  updated_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.vulnerability_work_items (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  source_connection_id uuid not null,
  finding_key text not null check (length(btrim(finding_key)) between 1 and 512),
  cve text check (cve is null or cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  source_agent_id text,
  status text not null default 'open'
    check (status in ('open', 'assigned', 'in_progress', 'remediation_applied', 'risk_accepted', 'false_positive')),
  assignee_user_id uuid,
  due_at timestamptz,
  justification text,
  created_by uuid references auth.users (id) on delete set null,
  updated_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, source_connection_id, finding_key),
  foreign key (tenant_id, source_connection_id)
    references public.wazuh_connections (tenant_id, id) on delete cascade,
  foreign key (tenant_id, assignee_user_id)
    references public.tenant_memberships (tenant_id, user_id) on delete set null (assignee_user_id),
  check (
    status not in ('risk_accepted', 'false_positive')
    or nullif(btrim(justification), '') is not null
  )
);

create table public.audit_log (
  id bigint generated always as identity primary key,
  tenant_id uuid references public.tenants (id) on delete set null,
  actor_user_id uuid references auth.users (id) on delete set null,
  event_type text not null check (event_type in ('insert', 'update', 'delete')),
  target_table text not null,
  target_key text not null,
  before_data jsonb,
  after_data jsonb,
  created_at timestamptz not null default now()
);

create index tenant_memberships_user_status_idx
  on public.tenant_memberships (user_id, status, tenant_id);
create index user_module_permissions_user_idx
  on public.user_module_permissions (user_id, tenant_id, module_key);
create index wazuh_connections_tenant_status_idx
  on public.wazuh_connections (tenant_id, status);
create index asset_classifications_critical_idx
  on public.asset_classifications (tenant_id, source_connection_id, is_critical);
create index vulnerability_work_items_queue_idx
  on public.vulnerability_work_items (tenant_id, status, due_at);
create index vulnerability_work_items_cve_idx
  on public.vulnerability_work_items (tenant_id, cve);
create index audit_log_tenant_time_idx
  on public.audit_log (tenant_id, created_at desc);
create index audit_log_actor_time_idx
  on public.audit_log (actor_user_id, created_at desc);

create or replace function public.pier360_is_aal2()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce((select auth.jwt() ->> 'aal') = 'aal2', false);
$$;

create or replace function public.pier360_is_super_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select public.pier360_is_aal2()
    and exists (
      select 1
      from public.global_capabilities as gc
      where gc.user_id = (select auth.uid())
        and gc.capability = 'platform.super_admin'
    );
$$;

create or replace function public.pier360_is_tenant_member(target_tenant_id uuid)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select public.pier360_is_aal2()
    and exists (
      select 1
      from public.tenant_memberships as tm
      where tm.tenant_id = target_tenant_id
        and tm.user_id = (select auth.uid())
        and tm.status = 'active'
    );
$$;

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

create or replace function public.pier360_set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create or replace function public.pier360_create_tenant_defaults()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.tenant_vulnerability_priority_configs (tenant_id, epss_threshold)
  values (new.id, 0.0880)
  on conflict (tenant_id) do nothing;
  return new;
end;
$$;

create or replace function public.pier360_capture_audit_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  old_row jsonb;
  new_row jsonb;
  current_row jsonb;
  row_key text;
  tenant_key uuid;
begin
  if tg_op in ('UPDATE', 'DELETE') then
    old_row := to_jsonb(old);
  end if;
  if tg_op in ('INSERT', 'UPDATE') then
    new_row := to_jsonb(new);
  end if;
  if tg_table_name = 'wazuh_connections' then
    old_row := old_row - 'secret_reference';
    new_row := new_row - 'secret_reference';
  end if;
  current_row := coalesce(new_row, old_row);

  if tg_table_name = 'tenants' then
    tenant_key := case when tg_op = 'DELETE' then null else nullif(current_row ->> 'id', '')::uuid end;
  else
    tenant_key := nullif(current_row ->> 'tenant_id', '')::uuid;
  end if;

  row_key := coalesce(
    current_row ->> 'id',
    nullif(concat_ws(':', current_row ->> 'tenant_id', current_row ->> 'user_id', current_row ->> 'module_key', current_row ->> 'capability'), ''),
    current_row ->> 'user_id',
    'unknown'
  );

  insert into public.audit_log (
    tenant_id, actor_user_id, event_type, target_table, target_key, before_data, after_data
  ) values (
    tenant_key, (select auth.uid()), lower(tg_op), 'public.' || tg_table_name, row_key, old_row, new_row
  );

  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

create or replace function public.pier360_prevent_last_super_admin()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  remaining_admins bigint;
begin
  if tg_op = 'DELETE' and old.capability = 'platform.super_admin' then
    select count(*) into remaining_admins
    from public.global_capabilities as gc
    where gc.capability = 'platform.super_admin'
      and gc.user_id <> old.user_id;
    if remaining_admins < 1 then
      raise exception 'The last PIER360 super admin cannot be removed';
    end if;
  elsif tg_op = 'UPDATE'
    and old.capability = 'platform.super_admin'
    and (new.capability is distinct from old.capability or new.user_id is distinct from old.user_id) then
    select count(*) into remaining_admins
    from public.global_capabilities as gc
    where gc.capability = 'platform.super_admin'
      and gc.user_id <> old.user_id;
    if remaining_admins < 1 then
      raise exception 'The last PIER360 super admin cannot be changed';
    end if;
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.tenant_memberships enable row level security;
alter table public.global_capabilities enable row level security;
alter table public.user_module_permissions enable row level security;
alter table public.wazuh_connections enable row level security;
alter table public.asset_classifications enable row level security;
alter table public.tenant_vulnerability_priority_configs enable row level security;
alter table public.vulnerability_work_items enable row level security;
alter table public.audit_log enable row level security;

create policy tenants_select_member_or_super_admin
  on public.tenants for select to authenticated
  using ((select public.pier360_is_super_admin()) or (select public.pier360_is_tenant_member(id)));
create policy tenants_manage_super_admin
  on public.tenants for all to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));

create policy profiles_select_self_or_super_admin
  on public.profiles for select to authenticated
  using (((select auth.uid()) = id and (select public.pier360_is_aal2())) or (select public.pier360_is_super_admin()));
create policy profiles_manage_super_admin
  on public.profiles for all to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));

create policy tenant_memberships_select_self_or_super_admin
  on public.tenant_memberships for select to authenticated
  using (((select auth.uid()) = user_id and (select public.pier360_is_aal2())) or (select public.pier360_is_super_admin()));
create policy tenant_memberships_manage_super_admin
  on public.tenant_memberships for all to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));

create policy global_capabilities_select_self_aal2
  on public.global_capabilities for select to authenticated
  using ((select auth.uid()) = user_id and (select public.pier360_is_aal2()));
create policy global_capabilities_insert_super_admin
  on public.global_capabilities for insert to authenticated
  with check ((select public.pier360_is_super_admin()));
create policy global_capabilities_update_super_admin
  on public.global_capabilities for update to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));
create policy global_capabilities_delete_super_admin
  on public.global_capabilities for delete to authenticated
  using ((select public.pier360_is_super_admin()));

create policy user_module_permissions_select_self_or_super_admin
  on public.user_module_permissions for select to authenticated
  using (((select auth.uid()) = user_id and (select public.pier360_is_aal2())) or (select public.pier360_is_super_admin()));
create policy user_module_permissions_manage_super_admin
  on public.user_module_permissions for all to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));

create policy wazuh_connections_select_authorized_tenant
  on public.wazuh_connections for select to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'assets', 'read'))
    or (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'read'))
  );
create policy wazuh_connections_manage_super_admin
  on public.wazuh_connections for all to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));

create policy asset_classifications_select_assets_module
  on public.asset_classifications for select to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'assets', 'read'))
  );
create policy asset_classifications_manage_assets_module
  on public.asset_classifications for all to authenticated
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

create policy priority_configs_select_authorized_tenant
  on public.tenant_vulnerability_priority_configs for select to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'dashboard', 'read'))
    or (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'read'))
  );
create policy priority_configs_manage_super_admin
  on public.tenant_vulnerability_priority_configs for all to authenticated
  using ((select public.pier360_is_super_admin()))
  with check ((select public.pier360_is_super_admin()));

create policy vulnerability_work_items_select_module
  on public.vulnerability_work_items for select to authenticated
  using (
    (select public.pier360_is_super_admin())
    or (select public.pier360_has_tenant_module(tenant_id, 'vulnerabilities', 'read'))
  );
create policy vulnerability_work_items_manage_module
  on public.vulnerability_work_items for all to authenticated
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

create policy audit_log_select_super_admin
  on public.audit_log for select to authenticated
  using ((select public.pier360_is_super_admin()));

create trigger tenants_set_updated_at before update on public.tenants
  for each row execute function public.pier360_set_updated_at();
create trigger profiles_set_updated_at before update on public.profiles
  for each row execute function public.pier360_set_updated_at();
create trigger memberships_set_updated_at before update on public.tenant_memberships
  for each row execute function public.pier360_set_updated_at();
create trigger connections_set_updated_at before update on public.wazuh_connections
  for each row execute function public.pier360_set_updated_at();
create trigger asset_classifications_set_updated_at before update on public.asset_classifications
  for each row execute function public.pier360_set_updated_at();
create trigger priority_configs_set_updated_at before update on public.tenant_vulnerability_priority_configs
  for each row execute function public.pier360_set_updated_at();
create trigger vulnerability_work_items_set_updated_at before update on public.vulnerability_work_items
  for each row execute function public.pier360_set_updated_at();

create trigger tenants_create_priority_defaults after insert on public.tenants
  for each row execute function public.pier360_create_tenant_defaults();
create trigger global_capabilities_protect_last_admin before update or delete on public.global_capabilities
  for each row execute function public.pier360_prevent_last_super_admin();

create trigger tenants_audit after insert or update or delete on public.tenants
  for each row execute function public.pier360_capture_audit_change();
create trigger profiles_audit after insert or update or delete on public.profiles
  for each row execute function public.pier360_capture_audit_change();
create trigger tenant_memberships_audit after insert or update or delete on public.tenant_memberships
  for each row execute function public.pier360_capture_audit_change();
create trigger global_capabilities_audit after insert or update or delete on public.global_capabilities
  for each row execute function public.pier360_capture_audit_change();
create trigger user_module_permissions_audit after insert or update or delete on public.user_module_permissions
  for each row execute function public.pier360_capture_audit_change();
create trigger wazuh_connections_audit after insert or update or delete on public.wazuh_connections
  for each row execute function public.pier360_capture_audit_change();
create trigger asset_classifications_audit after insert or update or delete on public.asset_classifications
  for each row execute function public.pier360_capture_audit_change();
create trigger priority_configs_audit after insert or update or delete on public.tenant_vulnerability_priority_configs
  for each row execute function public.pier360_capture_audit_change();
create trigger vulnerability_work_items_audit after insert or update or delete on public.vulnerability_work_items
  for each row execute function public.pier360_capture_audit_change();

revoke all on function public.pier360_is_aal2() from public, anon;
revoke all on function public.pier360_is_super_admin() from public, anon;
revoke all on function public.pier360_is_tenant_member(uuid) from public, anon;
revoke all on function public.pier360_has_tenant_module(uuid, text, text) from public, anon;
revoke all on function public.pier360_set_updated_at() from public, anon, authenticated;
revoke all on function public.pier360_create_tenant_defaults() from public, anon, authenticated;
revoke all on function public.pier360_capture_audit_change() from public, anon, authenticated;
revoke all on function public.pier360_prevent_last_super_admin() from public, anon, authenticated;
grant execute on function public.pier360_is_aal2() to authenticated;
grant execute on function public.pier360_is_super_admin() to authenticated;
grant execute on function public.pier360_is_tenant_member(uuid) to authenticated;
grant execute on function public.pier360_has_tenant_module(uuid, text, text) to authenticated;

grant usage on schema public to authenticated;
revoke all on table
  public.tenants,
  public.profiles,
  public.tenant_memberships,
  public.global_capabilities,
  public.user_module_permissions,
  public.asset_classifications,
  public.tenant_vulnerability_priority_configs,
  public.vulnerability_work_items,
  public.audit_log
from anon, authenticated;

grant select on table
  public.tenants,
  public.profiles,
  public.tenant_memberships,
  public.global_capabilities,
  public.user_module_permissions,
  public.asset_classifications,
  public.tenant_vulnerability_priority_configs,
  public.vulnerability_work_items,
  public.audit_log
to authenticated;

grant insert, update, delete on table
  public.tenants,
  public.tenant_memberships,
  public.global_capabilities,
  public.user_module_permissions,
  public.wazuh_connections,
  public.asset_classifications,
  public.tenant_vulnerability_priority_configs,
  public.vulnerability_work_items
to authenticated;

-- Never expose the connection secret reference through the browser Data API.
grant select (id, tenant_id, connection_key, display_name, status, created_at, updated_at)
  on table public.wazuh_connections to authenticated;
grant insert (tenant_id, connection_key, display_name, status),
  update (connection_key, display_name, status, updated_at),
  delete on table public.wazuh_connections to authenticated;
