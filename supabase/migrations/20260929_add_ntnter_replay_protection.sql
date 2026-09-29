-- F.U.R NTAG 424 DNA counter replay protection.
--
-- Stores the last accepted authenticated SDM read counter for each NFC UID.
-- Counter state is private and is intended for trusted server-side use only.

create table if not exists public.ntag424_counter_state (
  uid text primary key,
  last_counter integer not null,
  updated_at timestamptz not null default now(),

  constraint ntag424_counter_state_uid_format
    check (uid ~ '^[0-9A-Fa-f]{14}$'),

  constraint ntag424_counter_state_counter_range
    check (last_counter >= 0 and last_counter <= 16777215)
);

alter table public.ntag424_counter_state enable row level security;

comment on table public.ntag424_counter_state is
  'Private server-side state containing the last accepted authenticated NTAG 424 DNA SDM read counter for replay protection.';

comment on column public.ntag424_counter_state.last_counter is
  'Last authenticated 24-bit SDM read counter accepted for this NFC UID.';

create or replace function public.accept_ntag424_counter(
  p_uid text,
  p_counter integer
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid text;
  v_previous integer;
begin
  v_uid := upper(p_uid);

  if v_uid is null or v_uid !~ '^[0-9A-F]{14}$' then
    raise exception 'Invalid NTAG 424 DNA UID';
  end if;

  if p_counter is null or p_counter < 0 or p_counter > 16777215 then
    raise exception 'Invalid NTAG 424 DNA counter';
  end if;

  insert into public.ntag424_counter_state (
    uid,
    last_counter,
    updated_at
  )
  values (
    v_uid,
    p_counter,
    now()
  )
  on conflict (uid) do nothing;

  if found then
    return true;
  end if;

  select last_counter
    into v_previous
    from public.ntag424_counter_state
   where uid = v_uid
   for update;

  if p_counter <= v_previous then
    return false;
  end if;

  update public.ntag424_counter_state
     set last_counter = p_counter,
         updated_at = now()
   where uid = v_uid;

  return true;
end;
$$;

revoke all on table public.ntag424_counter_state from public;
revoke all on function public.accept_ntag424_counter(text, integer) from public;

grant execute on function public.accept_ntag424_counter(text, integer)
  to service_role;
