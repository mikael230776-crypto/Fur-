import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import handler, { validateSunMac } from "../api/verify.js";

const originalFetch = globalThis.fetch;
const environmentNames = [
  "SUPABASE_URL",
  "SUPABASE_SECRET_KEY",
  "ENABLE_SUN_VALIDATION",
  "SUN_SDM_FILE_READ_KEY"
];
const originalEnvironment = Object.fromEntries(
  environmentNames.map((name) => [name, process.env[name]])
);

function response(json) {
  return { ok: true, status: 200, json: async () => json, text: async () => "" };
}

function mockRes() {
  return {
    statusCode: 200,
    body: null,
    setHeader() {},
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const name of environmentNames) {
    if (originalEnvironment[name] === undefined) delete process.env[name];
    else process.env[name] = originalEnvironment[name];
  }
});

test("validates a deterministic NTAG 424 DNA SUN MAC", () => {
  assert.equal(
    validateSunMac(
      "044617DA291D90",
      "010000",
      "7355fad4c9c2d0bb",
      "00000000000000000000000000000000"
    ),
    true
  );
  assert.equal(
    validateSunMac(
      "044617DA291D90",
      "010000",
      "7355fad4c9c2d0ba",
      "00000000000000000000000000000000"
    ),
    false
  );
});

test("requires SUN data when validation is enabled", async () => {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
  process.env.ENABLE_SUN_VALIDATION = "true";
  process.env.SUN_SDM_FILE_READ_KEY = "00000000000000000000000000000000";
  let called = false;
  globalThis.fetch = async () => { called = true; };

  const res = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.message, "Missing SUN authentication data");
  assert.equal(called, false);
});

test("rejects a valid SUN MAC when its UID belongs to another tag", async () => {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
  process.env.ENABLE_SUN_VALIDATION = "true";
  process.env.SUN_SDM_FILE_READ_KEY = "00000000000000000000000000000000";
  globalThis.fetch = async () => response([{
    tag_id: "FUR-000001",
    tag_uid: "04-00-00-00-00-00-00",
    status: "ACTIVE"
  }]);

  const res = mockRes();
  await handler({ query: {
    tagId: "FUR-000001",
    uid: "044617DA291D90",
    ctr: "010000",
    cmac: "7355fad4c9c2d0bb"
  } }, res);

  assert.equal(res.statusCode, 403);
  assert.equal(res.body.status, "NOT_VERIFIED");
  assert.match(res.body.message, /UID does not match/);
});
