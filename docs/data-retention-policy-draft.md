# FUR Data Retention and Deletion Schedule

Status: DRAFT FOR PROFESSIONAL REVIEW — NOT LEGAL ADVICE — NOT YET IMPLEMENTED

Owner: [REQUIRED]
Approved by/date: [REQUIRED]
Review frequency: at least annually and whenever purposes, systems, law or risk change

## Principles

FUR will keep personal data only as long as necessary for a documented purpose. There is no single UK GDPR retention period. Each period below is a proposal that must be justified and approved before production use. Data due for disposal must be securely erased or irreversibly anonymised unless a documented legal hold applies.

Do not apply database migrations, schedule deletion jobs, or change production settings as part of this draft.

## Proposed schedule

| Record | Purpose | Proposed active retention | End-of-period action | Approval needed |
|---|---|---:|---|---|
| Verification scans: scan/request IDs, tag ID, result, time | product authentication, abuse/fraud investigation | 24 months from scan | delete or irreversibly aggregate/anonymise | confirm fraud investigation window and legitimate-interests assessment |
| Essential web/security logs held by infrastructure providers | security, availability, incident response | 90 days | automatic deletion | confirm provider defaults, access and backup behaviour |
| Administrator activity history | accountability, unauthorised-change investigation | 6 years from event | delete or anonymise actor ID where the event must be preserved | confirm proportionality and claims limitation needs |
| Physical inspection records | prove inspection outcome and product integrity | 6 years from inspection or end of relevant business relationship, whichever is later | delete identifiers and controlled evidence; retain anonymised result only if useful | confirm contractual/warranty and fraud requirements |
| Inspection evidence files | substantiate inspection | 12 months unless linked to an active dispute, investigation or warranty need | securely delete file and references | confirm evidence types and necessity |
| Administrator/inspector account profile | access control | account life plus 90 days | disable promptly; delete or anonymise after review | confirm authentication-provider retention |
| Business contract/account records | contract delivery, accounting and claims | 6 years after contract ends, unless a longer statutory duty applies | securely delete or restrict/archive where legally required | legal and tax review |
| Support and privacy correspondence | answer requests and demonstrate handling | 3 years after closure | securely delete | confirm complaint and claims needs |
| Data-subject request record | demonstrate lawful response | 3 years after closure | delete request content; retain minimal anonymised metrics | professional review |
| Consent record, if consent is used | demonstrate consent/withdrawal | duration of processing plus 6 years | delete when no longer required for claims/accountability | confirm consent use and proportionality |
| Suppression record, if direct marketing is introduced | respect objection/opt-out | while marketing continues, using minimum data | retain minimal suppression value; do not market | marketing review required before feature exists |
| Failed or abandoned application/onboarding data | manage application and disputes | 6 months after closure | securely delete | confirm whether this processing exists |
| Backups containing deleted records | resilience and disaster recovery | maximum 35 days after deletion from live systems | expire by rotation; prevent ordinary restoration/use | confirm Supabase/Vercel and other provider capabilities |

## Deletion process

1. The system owner produces a monthly report of records reaching the approved limit.
2. An authorised reviewer checks legal holds, active disputes, security investigations and statutory obligations.
3. Approved records are deleted or irreversibly anonymised using a tested, least-privilege process.
4. Related files, search indexes, analytics stores, exports and processor copies are included.
5. Backups expire through the approved rotation and are not restored into live use except for disaster recovery. Any restored expired data is deleted again before normal operation resumes.
6. The operator records the dataset, date range, count, action, approver and completion time without copying the deleted personal data into the deletion log.
7. Failures are alerted, investigated and rerun. Completion is sampled and verified.

## Legal holds

Deletion may be paused only when necessary for a documented legal claim, regulatory request, security investigation or statutory obligation. The hold must identify scope, owner, reason, start date, review date and release authority. Access must be restricted. When the hold ends, the normal retention rule resumes promptly.

## Individual-rights handling

A retention period does not automatically defeat an erasure request. Each request must be assessed under applicable law and exemptions. Where erasure is refused or restricted, FUR must record the reason, inform the person as required, and limit processing where appropriate.

## Data-quality and minimisation controls

- Do not store names, email addresses or free-form personal details in tag IDs, product descriptions, activity details or evidence references.
- Use opaque account/actor identifiers where practical.
- Store only evidence needed for the stated purpose.
- Separate operational data from legal-hold archives.
- Review access permissions at least quarterly and on role change or departure.

## Implementation gates

- [ ] Every system, processor, log, export and backup mapped
- [ ] Proposed periods justified and professionally approved
- [ ] Privacy notice updated with meaningful retention information
- [ ] Contracts require processors to delete or return data appropriately
- [ ] Deletion/anonymisation scripts peer-reviewed and tested on non-production data
- [ ] Legal-hold process tested
- [ ] Monitoring and deletion evidence defined
- [ ] Explicit approval obtained before any production job or migration

Official guidance: ICO Storage limitation, https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-protection-principles/a-guide-to-the-data-protection-principles/storage-limitation/
