# Phase 6 supplier sample acceptance

Use this checklist before approving any physical-authentication label, seal,
ink, taggant or reader for FUR. Complete one record for each supplier sample
and product variant. Do not approve production purchasing from specifications
alone.

## 1. Sample identity

- Supplier and product reference:
- Batch or lot number:
- Date received:
- Sample quantity:
- Intended FUR product and surface:
- Construction: label, seal, ink, taggant or combined NFC inlay:
- Supplier datasheet and safety documentation received: yes / no
- Claimed shelf life and storage conditions:

Reject the sample if its supplier, product reference or batch cannot be traced.

## 2. Required supplier answers

- Minimum order quantity and sample-to-production lead time
- Unit price at sample, pilot and expected production quantities
- Available dimensions, adhesives, face materials and print finishes
- Serialization method and duplicate-number controls
- Tamper response: destructible, VOID, delaminating or other
- UV excitation wavelength and visible response, where applicable
- Taggant reader model and calibration requirements, where applicable
- NFC chip/inlay model, antenna dimensions and encoding service, where applicable
- Environmental ratings and chemical-resistance data
- Evidence that production batches remain consistent with approved samples

Record unanswered items as open issues; do not infer them.

## 3. Visual and dimensional inspection

- Dimensions match the intended placement and permitted tolerance
- Printed FUR identifier is legible and matches the assigned identifier
- Human-readable and machine-readable identifiers agree
- No duplicate serial numbers are present in the received sample set
- Adhesive, inlay and security layers show no damage before application
- Supplier markings do not reveal secret or internal authentication data

## 4. Application test

Test only on representative sacrificial material, never on a production item.

- Clean and prepare the surface using the documented process
- Record application temperature, humidity and surface material
- Apply using the supplier's stated pressure and cure time
- Photograph the sample immediately after application
- Reinspect after the full cure period
- Confirm edges, corners and NFC inlay remain securely bonded

## 5. Tamper-evidence test

- Attempt slow peel, rapid peel and corner lift after curing
- Record whether the expected destructible, VOID or delamination response occurs
- Confirm the sample cannot be removed and reapplied without visible evidence
- Confirm the security response is clear under normal customer viewing conditions
- Photograph before, during and after the test

Pass only if every removal attempt produces the documented irreversible response.

## 6. UV or taggant test

- Use only the supplier-confirmed wavelength or approved reader
- Record lamp/reader manufacturer, model and wavelength or calibration ID
- Record ambient-light conditions and working distance
- Confirm the expected mark or taggant response is repeatable
- Confirm an untreated control sample does not produce the same response
- Confirm the response remains detectable after the environmental tests

Do not buy a UV lamp or specialist reader until the supplier confirms the exact
wavelength, power, safety requirements and compatible model range.

## 7. NFC compatibility test

- Confirm the exact NFC chip and antenna construction
- Confirm the tag reads reliably using supported customer phones
- Confirm the FUR verification URL opens correctly
- Confirm security material, metallic inks and product contents do not prevent a read
- Test at the intended installed position and orientation
- Record successful and failed reads without exposing keys or secret values

Do not write to either protected FUR tag during supplier evaluation. Use only
separate disposable test tags under an approved test plan.

## 8. Environmental test

Agree test severity for the intended customer use before testing.

- Low and high temperature exposure
- Humidity or condensation exposure
- Light/UV ageing where relevant
- Water, cleaning agent, oil or chemical contact where relevant
- Abrasion, flexing and handling
- Recheck adhesion, tamper response, UV/taggant response and NFC readability

## 9. Security and evidence record

- Assign a unique inspection record ID
- Store photographs in private evidence storage
- Calculate and record the SHA-256 hash of each evidence file
- Record the inspector identity, date, result and equipment used
- Keep supplier references private where disclosure would aid counterfeiting
- Record results as PRESENT, ABSENT, DAMAGED or INCONCLUSIVE
- Require a second review for any INCONCLUSIVE result

## 10. Acceptance decision

A sample can be accepted for a limited pilot only when:

- all mandatory supplier answers are complete;
- traceability and serialization controls pass;
- application and tamper tests pass;
- required UV/taggant checks pass with confirmed equipment;
- NFC compatibility passes at the intended installation position;
- environmental results meet the agreed customer use case; and
- evidence is complete and independently reviewable.

Decision: ACCEPT FOR PILOT / REJECT / MORE EVIDENCE REQUIRED

Approver:

Date:

Conditions or open issues:

## 11. Purchase gate

Before placing a pilot order, document:

- approved supplier, exact product reference and revision;
- pilot quantity and maximum spend;
- customer use case and environmental assumptions;
- required lamp/reader only after compatibility is confirmed;
- acceptance criteria for the delivered batch; and
- a stop condition if the delivered batch differs from the approved sample.

Production quantities require a separate approval after the pilot. Customer
demand may determine dimensions, material, environment and volume, but it must
not weaken traceability, tamper evidence or authentication requirements.
