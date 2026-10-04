create table if not exists public.dpp_passports (
  id uuid primary key default gen_random_uuid(),

  gtin text not null,
  serial_number text not null,
  fur_tag_id text not null,

  passport_version integer,
  passport_lifecycle_status text not null default 'DRAFT',

  replaces_passport_id uuid
    references public.dpp_passports(id),

  created_at timestamptz not null default now(),
  last_updated_at timestamptz not null default now(),

  constraint dpp_passports_identifier_unique
    unique (gtin, serial_number),

  constraint dpp_passports_gtin_format
    check (gtin ~ '^[0-9]{14}$'),

  constraint dpp_passports_serial_format
    check (serial_number ~ '^[A-Za-z0-9._-]{1,20}$'),

  constraint dpp_passports_lifecycle_valid
    check (
      passport_lifecycle_status in ('DRAFT', 'ACTIVE', 'RETIRED')
    ),

  constraint dpp_passports_version_state_valid
    check (
      (
        passport_lifecycle_status = 'DRAFT'
        and passport_version is null
      )
      or
      (
        passport_lifecycle_status in ('ACTIVE', 'RETIRED')
        and passport_version >= 1
      )
    )
);

create index if not exists idx_dpp_passports_fur_tag_id
  on public.dpp_passports (fur_tag_id);


create table if not exists public.dpp_passport_history (
  id uuid primary key default gen_random_uuid(),

  passport_id uuid not null
    references public.dpp_passports(id)
    on delete restrict,

  old_version integer,
  new_version integer not null,

  lifecycle_status text not null,

  changed_fields jsonb not null default '[]'::jsonb,

  actor text not null,
  actor_role text not null,

  approved_at timestamptz not null default now(),

  reason text not null,
  evidence_reference text,

  snapshot jsonb not null,

  constraint dpp_passport_history_version_unique
    unique (passport_id, new_version),

  constraint dpp_passport_history_old_version_valid
    check (
      old_version is null or old_version >= 1
    ),

  constraint dpp_passport_history_new_version_valid
    check (
      new_version >= 1
    ),

  constraint dpp_passport_history_version_order_valid
    check (
      old_version is null or new_version > old_version
    ),

  constraint dpp_passport_history_lifecycle_valid
    check (
      lifecycle_status in ('ACTIVE', 'RETIRED')
    )
);


create or replace function public.guard_dpp_passport_mutation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.created_at is distinct from old.created_at then
    raise exception 'DPP created_at is immutable';
  end if;

  if old.passport_lifecycle_status in ('ACTIVE', 'RETIRED') then
    if new.gtin is distinct from old.gtin
       or new.serial_number is distinct from old.serial_number
       or new.fur_tag_id is distinct from old.fur_tag_id then
      raise exception 'Active DPP identity is immutable';
    end if;
  end if;

  if new.passport_version is distinct from old.passport_version then
    if old.passport_version is null then
      if new.passport_version <> 1 then
        raise exception 'First ACTIVE DPP version must be 1';
      end if;
    elsif new.passport_version <> old.passport_version + 1 then
      raise exception 'DPP passport version must increment by exactly 1';
    end if;
  end if;

  if old.passport_lifecycle_status = 'DRAFT'
     and new.passport_lifecycle_status not in ('DRAFT', 'ACTIVE') then
    raise exception 'Invalid DPP lifecycle transition';
  end if;

  if old.passport_lifecycle_status = 'ACTIVE'
     and new.passport_lifecycle_status not in ('ACTIVE', 'RETIRED') then
    raise exception 'Invalid DPP lifecycle transition';
  end if;

  if old.passport_lifecycle_status = 'RETIRED'
     and new.passport_lifecycle_status <> 'RETIRED' then
    raise exception 'Retired DPP cannot be reactivated';
  end if;

  return new;
end;
$$;


drop trigger if exists dpp_passport_mutation_guard
on public.dpp_passports;

create trigger dpp_passport_mutation_guard
before update
on public.dpp_passports
for each row
execute function public.guard_dpp_passport_mutation();


create or replace function public.prevent_dpp_history_mutation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  raise exception 'DPP passport history is immutable';
end;
$$;


drop trigger if exists dpp_passport_history_immutable
on public.dpp_passport_history;

create trigger dpp_passport_history_immutable
before update or delete
on public.dpp_passport_history
for each row
execute function public.prevent_dpp_history_mutation();


alter table public.dpp_passports
  enable row level security;

alter table public.dpp_passport_history
  enable row level security;


revoke all on public.dpp_passports
  from anon, authenticated;

revoke all on public.dpp_passport_history
  from anon, authenticated;


grant select, insert, update
  on public.dpp_passports
  to service_role;

grant select, insert
  on public.dpp_passport_history
  to service_role;
