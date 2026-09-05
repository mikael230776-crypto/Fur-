import test from "node:test";
import assert from "node:assert/strict";
import handler, { adminEnabled, authorized, validateInspection } from "../api/physical-inspection-admin.js";

const valid = {
  profileId: "123e4567-e89b-42d3-a456-426614174000",
  tagId: "FUR-000001",
  result: "present",
  inspectorId: "inspector@example.com",
  evidenceSha256: "A".repeat(64),
  evidenceReference: "private/evidence/inspection-1"
};

function mockResponse() {
  return {
    statusCode: 200, headers: {}, body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }
  };
}

test("admin recording is disabled by default", () => {
  delete process.env.ENABLE_PHYSICAL_AUTH_ADMIN;
  assert.equal(adminEnabled(), false);
});

test("requires an exact bearer token", () => {
  assert.equal(authorized("Bearer correct", "correct"), true);
  assert.equal(authorized("Bearer wrong", "correct"), false);
  assert.equal(authorized("correct", "correct"), false);
  assert.equal(authorized(undefined, "correct"), false);
});

test("normalizes valid inspection evidence", () => {
  const result = validateInspection(valid);
  assert.equal(result.ok, true);
  assert.equal(result.value.result, "PRESENT");
  assert.equal(result.value.evidence_sha256, "a".repeat(64));
});

test("rejects invalid or unsupported data", () => {
  for (const input of [null, { ...valid, profileId: "no" }, { ...valid, tagId: "FUR-1" }, { ...valid, result: "PASS" }, { ...valid, inspectorId: "space not allowed" }, { ...valid, evidenceSha256: "abc" }, { ...valid, unexpected: true }]) {
    assert.equal(validateInspection(input).ok, false);
  }
});

test("returns 404 without storage access when disabled", async () => {
  delete process.env.ENABLE_PHYSICAL_AUTH_ADMIN;
  const originalFetch = global.fetch;
  global.fetch = async () => assert.fail("fetch must not run");
  try {
    const res = mockResponse();
    await handler({ method: "POST", headers: {}, body: valid }, res);
    assert.equal(res.statusCode, 404);
  } finally { global.fetch = originalFetch; }
});

test("rejects unauthorized requests when enabled", async () => {
  process.env.ENABLE_PHYSICAL_AUTH_ADMIN = "true";
  process.env.PHYSICAL_AUTH_ADMIN_TOKEN = "correct";
  const res = mockResponse();
  await handler({ method: "POST", headers: { authorization: "Bearer wrong" }, body: valid }, res);
  assert.equal(res.statusCode, 401);
  delete process.env.ENABLE_PHYSICAL_AUTH_ADMIN;
  delete process.env.PHYSICAL_AUTH_ADMIN_TOKEN;
});

test("records validated evidence with server credentials", async () => {
  process.env.ENABLE_PHYSICAL_AUTH_ADMIN = "true";
  process.env.PHYSICAL_AUTH_ADMIN_TOKEN = "correct";
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "server-secret";
  const originalFetch = global.fetch;
  let request;
  global.fetch = async (url, options) => {
    request = { url, options };
    return { ok: true, json: async () => [{ inspection_id: "inspection-1", result: "PRESENT", inspected_at: "2026-09-05T12:00:00Z" }] };
  };
  try {
    const res = mockResponse();
    await handler({ method: "POST", headers: { authorization: "Bearer correct" }, body: valid }, res);
    assert.equal(res.statusCode, 201);
    assert.equal(res.body.inspectionId, "inspection-1");
    assert.equal(request.options.headers.Authorization, "Bearer server-secret");
    assert.equal(JSON.parse(request.options.body).tag_id, "FUR-000001");
  } finally {
    global.fetch = originalFetch;
    for (const name of ["ENABLE_PHYSICAL_AUTH_ADMIN", "PHYSICAL_AUTH_ADMIN_TOKEN", "SUPABASE_URL", "SUPABASE_SECRET_KEY"]) delete process.env[name];
  }
});
