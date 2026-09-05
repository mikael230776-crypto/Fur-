# Step 8 — UK GDPR review

Status: DRAFT FOR PROFESSIONAL REVIEW — NOT LEGAL ADVICE — NOT FOR PUBLICATION

Reviewed: 5 September 2026
Scope: the current FUR repository and planned administration foundation. This review does not activate features, apply migrations, or change production data.

## Controller details required before launch

- Legal/controller name: [REQUIRED]
- Registered or correspondence address: [REQUIRED]
- Privacy contact email: [REQUIRED]
- Data Protection Officer, if appointed: [NOT YET DETERMINED]
- ICO registration/fee status: [REVIEW REQUIRED]

## Current data map

| Processing area | Data visible in repository | Likely people concerned | Purpose | Status |
|---|---|---|---|---|
| NFC verification | scan UUID, FUR tag ID, request UUID, result status, scan time | product holder or scanner indirectly | authenticate products and investigate suspicious repeat scans | implemented server-side |
| Physical inspection | profile/tag IDs, result, inspector ID, evidence hash/reference, inspection and creation times | inspectors; product holders indirectly | factory authentication and evidence trail | migration drafted, not applied |
| Administration | actor ID, role, action, product ID, structured details, event time | administrators | product administration, authorisation and accountability | disabled foundation; migration not applied |
| Product records | SKU, product name/description, state and timestamps | normally no individual; may become personal if free text identifies someone | manage FUR products | disabled foundation |

The repository search found no deliberate storage of names, email addresses, postal addresses or IP addresses in these tables. Hosting, logging, authentication and support providers may nevertheless process IP addresses, account identifiers, device data or correspondence; these must be confirmed from live provider settings and contracts.

## UK GDPR checklist

### 1. Roles and responsibility

- Confirm the data controller and privacy contact.
- List processors, currently expected to include hosting/database providers where applicable.
- Put Article 28-compliant processor terms in place and record subprocessors.
- Establish who answers data-subject requests and security incidents.

### 2. Purpose and lawful basis

Document one lawful basis for every purpose before processing begins. Likely candidates requiring professional confirmation:

- product verification and fraud/security monitoring: legitimate interests may be appropriate only after a documented balancing test;
- administrator and inspector security logs: legitimate interests and/or legal obligation, depending on the precise obligation;
- business account or contractual administration: contract may apply where processing is necessary for that contract.

Do not use consent by default. If consent is used, it must be freely given, specific, informed, unambiguous, recorded and as easy to withdraw as to give.

### 3. Transparency

Provide a concise, accessible privacy notice at or before direct collection. For data obtained indirectly, provide the required information within the applicable period, normally no later than one month, subject to lawful exceptions. The notice must explain purposes, lawful bases, recipients, transfers, retention, rights, complaint routes and any automated decision-making.

### 4. Data minimisation and security

- Keep opaque identifiers rather than names where operationally sufficient.
- Prohibit personal data in free-text product descriptions, activity details and evidence references.
- Restrict administrator, inspector and service-role access by least privilege.
- Keep row-level security enabled and test denial paths.
- Never expose service-role keys in client code or logs.
- Define encryption, backup, secret rotation, incident response and breach-assessment procedures.

### 5. Retention and deletion

The UK GDPR does not prescribe one universal retention period. FUR must justify each period against its purpose, review records periodically, and securely erase or irreversibly anonymise data when no longer needed. A separate draft retention schedule is required, including backups, logs, evidence, legal holds and deletion verification.

### 6. Individual rights

Create procedures for access, rectification, erasure, restriction, objection, portability where applicable, and complaints. Verify identity proportionately, record deadlines, search all processors/backups, and document decisions and exemptions.

### 7. DPIA and risk review

Complete a screening assessment before launch. A DPIA is required where processing is likely to create a high risk to people. Reassess if FUR introduces systematic monitoring, location/device tracking, profiling, large-scale datasets, biometric data, linkage across datasets, or decisions with significant effects. Consult the ICO before processing if high residual risk cannot be reduced.

### 8. International transfers

Map where every provider and subprocessor stores or remotely accesses data. If personal data leaves the UK, document the applicable adequacy regulation or safeguard, transfer risk assessment where required, and supplementary measures.

### 9. Cookies and analytics

Inventory cookies, SDKs, analytics, error monitoring and deployment logs. Do not place non-essential cookies or run non-essential tracking before valid consent. Ensure rejection is as accessible as acceptance and honour withdrawal.

### 10. Children and vulnerable users

Determine whether children are likely to use FUR. If so, perform an age-appropriate design and transparency review before launch and apply enhanced safeguards.

## Launch blockers

- [ ] Controller identity, address and privacy contact confirmed
- [ ] Complete live-system and provider data map
- [ ] Lawful-basis assessment and legitimate-interests assessments approved
- [ ] Privacy notice completed and professionally reviewed
- [ ] Retention schedule approved and technically enforceable
- [ ] Processor/subprocessor contracts and international transfers reviewed
- [ ] Rights-request and incident-response procedures tested
- [ ] DPIA screening completed; DPIA completed if required
- [ ] Cookie/tracker audit completed
- [ ] ICO fee/registration position checked
- [ ] Security tests and access-control review passed
- [ ] Explicit approval obtained before publication or production enablement

## Official sources checked

- ICO, Right to be informed: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-be-informed/
- ICO, Storage limitation: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/storage-limitation/
- ICO, DPIAs: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/data-protection-impact-assessments-dpias/

ICO guidance should be rechecked immediately before professional approval and launch because it is being updated following legislative changes.
