const PHYSICAL_AUTH_METHODS = new Set([
  "TAMPER_EVIDENT",
  "UV_MARK",
  "MACHINE_TAGGANT",
  "FORENSIC_MARKER"
]);

const PASS_RESULTS = new Set(["PRESENT"]);
const FAIL_RESULTS = new Set(["ABSENT", "DAMAGED"]);

function physicalAuthEnabled() {
  return process.env.ENABLE_PHYSICAL_AUTH === "true";
}

function publicPhysicalAuthSummary(profile, inspection) {
  if (!profile) {
    return { required: false, status: "NOT_REQUIRED" };
  }

  const method = PHYSICAL_AUTH_METHODS.has(profile.method)
    ? profile.method
    : "OTHER";
  const result = inspection?.result;
  let status = "NOT_INSPECTED";

  if (PASS_RESULTS.has(result)) status = "PASSED";
  if (FAIL_RESULTS.has(result)) status = "FAILED";
  if (result === "INCONCLUSIVE") status = "REVIEW_REQUIRED";

  return {
    required: true,
    method,
    status,
    inspectedAt: inspection?.inspected_at ?? null
  };
}

async function getPhysicalAuthSummary(
  supabaseUrl,
  supabaseSecretKey,
  tagId,
  headers
) {
  const profileEndpoint =
    `${supabaseUrl}/rest/v1/physical_auth_profiles` +
    `?tag_id=eq.${encodeURIComponent(tagId)}` +
    `&status=eq.ACTIVE` +
    `&select=profile_id,method` +
    `&limit=1`;
  const profileResponse = await fetch(profileEndpoint, { headers });

  if (!profileResponse.ok) {
    return { ok: false, message: "Physical authentication profile lookup failed" };
  }

  const profile = (await profileResponse.json())[0];
  if (!profile) {
    return { ok: true, summary: publicPhysicalAuthSummary(null, null) };
  }

  const inspectionEndpoint =
    `${supabaseUrl}/rest/v1/physical_inspections` +
    `?profile_id=eq.${encodeURIComponent(profile.profile_id)}` +
    `&select=result,inspected_at` +
    `&order=inspected_at.desc` +
    `&limit=1`;
  const inspectionResponse = await fetch(inspectionEndpoint, { headers });

  if (!inspectionResponse.ok) {
    return { ok: false, message: "Physical inspection lookup failed" };
  }

  const inspection = (await inspectionResponse.json())[0];
  return {
    ok: true,
    summary: publicPhysicalAuthSummary(profile, inspection)
  };
}

export {
  getPhysicalAuthSummary,
  physicalAuthEnabled,
  publicPhysicalAuthSummary
};
