-- FUR Phase 6: vendor-neutral physical authentication evidence.
--
-- These tables are private. Evidence must only be written by a trusted future
-- administration workflow; the public verification endpoint is read-only.

create table if not exists public.physical_auth_profiles (
  profile_id uuid primary key default gen_random_uuid(),
  tag_id text not null unique,
  method text not null,
  status text not null default 'ACTIVE',
  supplier_reference text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint physical_auth_profiles_tag_id_format
    check (tag_id ~ '^FUR-[0-9]{6}$'),
  constraint physical_auth_profiles_method
    check (method in (
      'TAMPER_EVIDENT',
      'UV_MARK',
      'MACHINE_TAGGANT',
      'FORENSIC_MARKER'
    )),
  constraint physical_auth_profiles_status
    check (status in ('ACTIVE', 'INACTIVE'))
);

create table if not exists public.physical_inspections (
  inspection_id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.physical_auth_profiles(profile_id),
  tag_id text not null,
  result text not null,
  inspector_id text not null,
  evidence_sha256 text,
  evidence_reference text,
  inspected_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  constraint physical_inspections_tag_id_format
    check (tag_id ~ '^FUR-[0-9]{6}$'),
  constraint physical_inspections_result
    check (result in ('PRESENT', 'ABSENT', 'DAMAGED', 'INCONCLUSIVE')),
  constraint physical_inspections_evidence_sha256
    check (evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$')
);

create index if not exists physical_inspections_profile_time_idx
  on public.physical_inspections (profile_id, inspected_at desc);

create index if not exists physical_inspections_tag_time_idx
  on public.physical_inspections (tag_id, inspected_at desc);

alter table public.physical_auth_profiles enable row level security;
alter table public.physical_inspections enable row level security;

comment on table public.physical_auth_profiles is
  'Private FUR physical-authentication requirements bound to registered tags.';
comment on table public.physical_inspections is
  'Private append-only evidence ledger for trusted physical inspections.';
