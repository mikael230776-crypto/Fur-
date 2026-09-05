import { randomUUID, timingSafeEqual } from "node:crypto";

const TAG_ID_PATTERN = /^FUR-[0-9]{6}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const RESULTS = new Set(["PRESENT", "ABSENT", "DAMAGED", "INCONCLUSIVE"]);

function adminEnabled() {
  return process.env.ENABLE_PHYSICAL_AUTH_ADMIN === "true";
}

function authorized(header, expectedToken) {
  if (!expectedToken || typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(expectedToken);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function validateInspection(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, message: "A JSON inspection object is required" };
  }
  const allowed = new Set(["profileId", "tagId", "result", "inspectorId", "evidenceSha256", "evidenceReference"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    return { ok: false, message: "Inspection contains unsupported fields" };
  }
  const profileId = String(input.profileId ?? "").trim();
  const tagId = String(input.tagId ?? "").trim();
  const result = String(input.result ?? "").trim().toUpperCase();
  const inspectorId = String(input.inspectorId ?? "").trim();
  const evidenceSha256 = input.evidenceSha256 == null ? null : String(input.evidenceSha256).trim().toLowerCase();
  const evidenceReference = input.evidenceReference == null ? null : String(input.evidenceReference).trim();

  if (!UUID_PATTERN.test(profileId)) return { ok: false, message: "Invalid profileId" };
  if (!TAG_ID_PATTERN.test(tagId)) return { ok: false, message: "Invalid tagId" };
  if (!RESULTS.has(result)) return { ok: false, message: "Invalid inspection result" };
  if (!/^[A-Za-z0-9._@-]{1,120}$/.test(inspectorId)) return { ok: false, message: "Invalid inspectorId" };
  if (evidenceSha256 !== null && !SHA256_PATTERN.test(evidenceSha256)) return { ok: false, message: "Invalid evidenceSha256" };
  if (evidenceReference !== null && (evidenceReference.length < 1 || evidenceReference.length > 500)) {
    return { ok: false, message: "Invalid evidenceReference" };
  }
  return { ok: true, value: { profile_id: profileId, tag_id: tagId, result, inspector_id: inspectorId, evidence_sha256: evidenceSha256, evidence_reference: evidenceReference } };
}

export default async function handler(req, res) {
  const requestId = randomUUID();
  res.setHeader?.("Cache-Control", "no-store");
  res.setHeader?.("X-Request-Id", requestId);
  if ((req.method || "GET").toUpperCase() !== "POST") {
    res.setHeader?.("Allow", "POST");
    return res.status(405).json({ ok: false, requestId, message: "Method not allowed" });
  }
  if (!adminEnabled()) return res.status(404).json({ ok: false, requestId, message: "Not found" });
  if (!authorized(req.headers?.authorization, process.env.PHYSICAL_AUTH_ADMIN_TOKEN)) {
    return res.status(401).json({ ok: false, requestId, message: "Unauthorized" });
  }
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(503).json({ ok: false, requestId, message: "Service unavailable" });
  }
  const validated = validateInspection(req.body);
  if (!validated.ok) return res.status(400).json({ ok: false, requestId, message: validated.message });

  const response = await fetch(`${supabaseUrl}/rest/v1/physical_inspections`, {
    method: "POST",
    headers: { Authorization: `Bearer ${supabaseSecretKey}`, apikey: supabaseSecretKey, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify(validated.value)
  });
  if (!response.ok) {
    console.error("Physical inspection insert failed", response.status, requestId);
    return res.status(502).json({ ok: false, requestId, message: "Inspection was not recorded" });
  }
  const record = (await response.json())[0];
  return res.status(201).json({ ok: true, requestId, inspectionId: record?.inspection_id ?? null, result: record?.result ?? validated.value.result, inspectedAt: record?.inspected_at ?? null });
}

export { adminEnabled, authorized, validateInspection };
