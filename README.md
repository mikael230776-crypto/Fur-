# FUR Verification

FUR is developing a professional product verification service. Phase 1 uses NFC-linked product identifiers to let a customer check whether a product record is recognised and currently verified.

## Phase 1

Current Phase 1 flow:

1. An NFC tag directs the customer to the FUR verification page with a tag ID.
2. The public page sends the tag ID to the verification API.
3. The API validates and normalises the tag ID.
4. The API checks the FUR product registry in Supabase.
5. A verified product returns its product, brand and verification status.
6. The service creates or reuses a persistent verification record for the verified tag.

Phase 1 is NFC-only. Later development can extend the system with additional physical authentication technology.

## Phase 6 foundation: NFC plus physical evidence

Phase 6 adds a vendor-neutral physical-authentication layer without weakening
the NTAG 424 DNA checks. A product can be assigned one active method:

- `TAMPER_EVIDENT`
- `UV_MARK`
- `MACHINE_TAGGANT`
- `FORENSIC_MARKER`

Trusted inspections record `PRESENT`, `ABSENT`, `DAMAGED` or `INCONCLUSIVE`
in a private append-only evidence ledger. The public verification endpoint can
read the latest result but cannot submit or change inspection evidence.

The integration is disabled by default. Enable it only after applying the
Phase 6 database migration and configuring trusted administration controls:

```text
ENABLE_PHYSICAL_AUTH=true
```

When enabled, a required physical check can produce
`PHYSICAL_CHECK_REQUIRED`, `REVIEW_REQUIRED` or `NOT_VERIFIED`. Only a passed
physical inspection can preserve the final `VERIFIED` result for a product
with an active physical-authentication profile.

## Tag format

Valid product tag IDs use this format:

```text
FUR-000001
```

The API trims surrounding spaces and converts letters to uppercase before checking the tag.

## Verification API

Endpoint:

```text
GET /api/verify?tagId=FUR-000001
```

Main response states include:

- `VERIFIED` — the registry contains a currently verified product.
- `NOT_VERIFIED` — the product is not recognised or is not currently verified.
- `ERROR` — the verification service could not complete the request.

The API stores successful verification records in Supabase so verified scans have a persistent audit record.

## Current protections

The public verification endpoint currently includes:

- GET-only method protection.
- Tag ID format validation.
- Per-client request rate limiting.
- No-cache response headers.
- Request IDs and structured request logging.
- Clear separation between an unknown product and a service failure.
- Optional NTAG 424 DNA SUN authentication using an AES-128 SDM file-read key.
- Constant-time comparison of the received and calculated SUN MAC.
- Binding of the authenticated NFC UID to the UID stored in the FUR Registry.

## Data and secrets

Supabase connection details are supplied through environment variables:

```text
SUPABASE_URL
SUPABASE_SECRET_KEY
```

Scan history and SUN validation are enabled independently:

```text
ENABLE_SCAN_HISTORY=true
ENABLE_SUN_VALIDATION=true
SUN_SDM_FILE_READ_KEY=<32 hexadecimal characters>
```

When SUN validation is enabled, the tag URL must provide `uid`, `ctr` and
`cmac` alongside `tagId`. `SUN_SDM_FILE_READ_KEY` is a server-only AES-128 key
and must match the key used when provisioning the NTAG 424 DNA tag. The current
MAC calculation is for the FUR SDM profile where the MAC input is empty; do not
enable it for a differently configured tag profile.

Secret keys must never be committed to this repository or exposed in client-side code.

The trusted inspection write endpoint is separately disabled by default. When
it is eventually deployed, it requires these server-only values:

```text
ENABLE_PHYSICAL_AUTH_ADMIN=true
PHYSICAL_AUTH_ADMIN_TOKEN=<long random server-only token>
```

`POST /api/physical-inspection-admin` accepts a strictly validated inspection
for an existing physical-authentication profile. Never place the admin token in
a browser, NFC payload, QR code, repository file or customer-facing application.

## Tests

Run the automated test suite with:

```bash
npm test
```

The test suite covers the verification API behaviour, including valid and invalid tags, persistence, service failures and request protection.

## Development approach

Changes should be developed on a separate branch and reviewed through a pull request before they reach `main`. The working verification service on `main` should remain stable while new functionality is developed.
