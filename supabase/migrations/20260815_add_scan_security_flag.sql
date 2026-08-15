alter table public.verification_scans
  add column if not exists security_flag text;

comment on column public.verification_scans.security_flag is
  'FUR-controlled security flag for suspicious NFC verification activity.';
