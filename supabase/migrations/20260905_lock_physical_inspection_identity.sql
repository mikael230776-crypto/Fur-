-- Prevent an inspection from naming a tag that differs from its profile.
alter table public.physical_auth_profiles
  add constraint physical_auth_profiles_profile_tag_unique
  unique (profile_id, tag_id);

alter table public.physical_inspections
  add constraint physical_inspections_profile_tag_fk
  foreign key (profile_id, tag_id)
  references public.physical_auth_profiles (profile_id, tag_id);
