-- Step 7 administration foundation. REVIEW ONLY: do not apply during Phase 6 hold.
begin;

create table if not exists public.admin_products (
  product_id text primary key default gen_random_uuid()::text,
  sku text not null unique,
  name text not null,
  description text,
  status text not null default 'active',
  suspension_reason text,
  suspended_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint admin_products_sku_format check (sku ~ '^[A-Z0-9][A-Z0-9._-]{1,63}$'),
  constraint admin_products_name_length check (char_length(name) between 1 and 200),
  constraint admin_products_description_length check (description is null or char_length(description) <= 2000),
  constraint admin_products_status check (status in ('active', 'suspended')),
  constraint admin_products_suspension_state check (
    (status = 'active' and suspension_reason is null and suspended_at is null)
    or
    (status = 'suspended' and suspension_reason is not null and suspended_at is not null)
  )
);

create table if not exists public.admin_activity_history (
  event_id bigint generated always as identity primary key,
  actor_id text not null,
  actor_role text not null,
  action text not null,
  product_id text not null references public.admin_products(product_id),
  details jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now(),
  constraint admin_activity_actor_id_length check (char_length(actor_id) between 1 and 120),
  constraint admin_activity_actor_role check (actor_role in ('viewer', 'editor', 'administrator')),
  constraint admin_activity_action check (action in ('product.add', 'product.update', 'product.suspend')),
  constraint admin_activity_details_object check (jsonb_typeof(details) = 'object')
);

create index if not exists admin_activity_product_time_idx
  on public.admin_activity_history (product_id, occurred_at desc);

create or replace function public.reject_admin_activity_change()
returns trigger
language plpgsql
as $$
begin
  raise exception 'admin activity history is append-only' using errcode = '55000';
end;
$$;

drop trigger if exists admin_activity_history_immutable on public.admin_activity_history;
create trigger admin_activity_history_immutable
before update or delete on public.admin_activity_history
for each row execute function public.reject_admin_activity_change();

alter table public.admin_products enable row level security;
alter table public.admin_activity_history enable row level security;

revoke all on public.admin_products from public, anon, authenticated;
revoke all on public.admin_activity_history from public, anon, authenticated;
revoke all on sequence public.admin_activity_history_event_id_seq from public, anon, authenticated;

create or replace function public.admin_mutate_product(
  p_operation text,
  p_actor_id text,
  p_actor_role text,
  p_product_id text default null,
  p_sku text default null,
  p_name text default null,
  p_description text default null,
  p_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_product public.admin_products%rowtype;
  v_action text;
begin
  if p_actor_id is null or char_length(btrim(p_actor_id)) not between 1 and 120 then
    raise exception 'invalid actor' using errcode = '22023';
  end if;

  if p_operation = 'add' then
    if p_actor_role not in ('editor', 'administrator') then
      raise exception 'forbidden' using errcode = '42501';
    end if;
    insert into public.admin_products (sku, name, description)
    values (p_sku, p_name, p_description)
    returning * into strict v_product;
    v_action := 'product.add';

  elsif p_operation = 'update' then
    if p_actor_role not in ('editor', 'administrator') then
      raise exception 'forbidden' using errcode = '42501';
    end if;
    update public.admin_products
       set name = p_name,
           description = p_description,
           updated_at = now()
     where product_id = p_product_id
       and status = 'active'
    returning * into strict v_product;
    v_action := 'product.update';

  elsif p_operation = 'suspend' then
    if p_actor_role <> 'administrator' then
      raise exception 'forbidden' using errcode = '42501';
    end if;
    if p_reason is null or char_length(btrim(p_reason)) not between 1 and 500 then
      raise exception 'invalid suspension reason' using errcode = '22023';
    end if;
    update public.admin_products
       set status = 'suspended',
           suspension_reason = btrim(p_reason),
           suspended_at = now(),
           updated_at = now()
     where product_id = p_product_id
       and status = 'active'
    returning * into strict v_product;
    v_action := 'product.suspend';

  else
    raise exception 'invalid operation' using errcode = '22023';
  end if;

  insert into public.admin_activity_history (actor_id, actor_role, action, product_id, details)
  values (
    btrim(p_actor_id),
    p_actor_role,
    v_action,
    v_product.product_id,
    jsonb_strip_nulls(jsonb_build_object('sku', v_product.sku, 'reason', p_reason))
  );

  return to_jsonb(v_product);
end;
$$;

revoke all on function public.admin_mutate_product(text, text, text, text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.admin_mutate_product(text, text, text, text, text, text, text, text) to service_role;

comment on table public.admin_products is
  'Disabled Step 7 administration foundation; access is server-side only.';
comment on table public.admin_activity_history is
  'Append-only administration activity history; update and delete are blocked.';

commit;
