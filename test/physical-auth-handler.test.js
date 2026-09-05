import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import handler from "../api/verify.js";

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  delete process.env.ENABLE_PHYSICAL_AUTH;
  delete process.env.ENABLE_SCAN_HISTORY;
  delete process.env.ENABLE_SUN_VALIDATION;
});

function res() {
  return {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }
  };
}

function response(json, ok = true) {
  return { ok, status: ok ? 200 : 500, json: async () => json, text: async () => "" };
}

function configure() {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
  process.env.ENABLE_PHYSICAL_AUTH = "true";
}

function baseFetch(inspection) {
  return async (url, options = {}) => {
    if (url.includes("/nfc_tags")) {
      return response([{ tag_id: "FUR-000001", tag_uid: "044517DA291D90", status: "ACTIVE" }]);
    }
    if (url.includes("/Products")) {
      return response([{ tag_id: "FUR-000001", product: "Bag", brand: "FUR", status: "VERIFIED" }]);
    }
    if (url.includes("/physical_auth_profiles")) {
      return response([{ profile_id: "profile-1", method: "UV_MARK" }]);
    }
    if (url.includes("/physical_inspections")) {
      return response(inspection ? [inspection] : []);
    }
    if (url.includes("/verification_records") && options.method === "POST") {
      return response([{ ...JSON.parse(options.body), created_at: "2026-09-05T10:00:00Z" }]);
    }
    if (url.includes("/verification_records")) return response([]);
    throw new Error(`Unexpected endpoint: ${url}`);
  };
}

test("requires a physical check when an assigned profile has no evidence", async () => {
  configure();
  global.fetch = baseFetch(null);
  const result = res();

  await handler({ method: "GET", query: { tagId: "FUR-000001" } }, result);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.status, "PHYSICAL_CHECK_REQUIRED");
  assert.deepEqual(result.body.physicalAuthentication, {
    required: true,
    method: "UV_MARK",
    status: "NOT_INSPECTED",
    inspectedAt: null
  });
});

test("fails verification when the latest physical evidence is damaged", async () => {
  configure();
  global.fetch = baseFetch({ result: "DAMAGED", inspected_at: "2026-09-05T10:00:00Z" });
  const result = res();

  await handler({ method: "GET", query: { tagId: "FUR-000001" } }, result);

  assert.equal(result.statusCode, 403);
  assert.equal(result.body.status, "NOT_VERIFIED");
  assert.equal(result.body.physicalAuthentication.status, "FAILED");
});

test("returns verified when NFC and physical evidence both pass", async () => {
  configure();
  global.fetch = baseFetch({ result: "PRESENT", inspected_at: "2026-09-05T10:00:00Z" });
  const result = res();

  await handler({ method: "GET", query: { tagId: "FUR-000001" } }, result);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.status, "VERIFIED");
  assert.equal(result.body.physicalAuthentication.status, "PASSED");
});
