ALTER TABLE nfc_tags
  ADD COLUMN last_verified_counter bigint NOT NULL DEFAULT -1;

COMMENT ON COLUMN nfc_tags.last_verified_counter IS
  'Highest NTAG 424 DNA SDM counter value accepted for this tag. Used to reject replayed SUN scans.';
