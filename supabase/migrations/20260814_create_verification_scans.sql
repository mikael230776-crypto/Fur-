-- FUR Phase 1 NFC security groundwork.
--
-- This table records each verification scan separately from the permanent
-- verification record. A scan history is required before FUR can detect
-- suspicious repeated use of the same NFC tag identity.

create extension if not exists pgcrypto;

create table if not exists public.verification_scans (
  scan_id uuid primary key default gen_random_uuid(),
  tag_id text not null,
  request_id uuid not null,
  result_status text not null,
  scanned_at timestamptz not null default now(),
  constraint verification_scans_tag_id_format
    check (tag_id ~ '^FUR-[0-9]{6}$')
);

create index if not exists verification_scans_tag_time_idx
  on public.verification_scans (tag_id, scanned_at desc);

-- Keep scan history private. The verification API uses the Supabase secret
-- key server-side, while public/anonymous clients should not read this table.
alter table public.verification_scans enable row level security;

comment on table public.verification_scans is
  'Server-side scan history used for FUR NFC verification security analysis.';
