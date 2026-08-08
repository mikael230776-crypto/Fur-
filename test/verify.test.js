import test from "node:test";
import assert from "node:assert/strict";
import handler, { createVerificationId } from "../api/verify.js";

function mockRes() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    }
  };
}

function response({ ok = true, status = 200, json = [], text = "" } = {}) {
  return {
    ok,
    status,
    json: async () => json,
    text: async () => text
  };
}

function verifiedProduct() {
  return {
    tag_id: "FUR-000001",
    product: "Bag",
    brand: "FUR",
    status: "VERIFIED"
  };
}

function configureSupabase() {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
}

test("persists and returns verification record", async () => {
  configureSupabase();
  const calls = [];
  const createdAt = "2026-08-08T09:00:00.000Z";

  global.fetch = async (url, options = {}) => {
    calls.push({ url, options });

    if (calls.length === 1) {
      return response({ json: [verifiedProduct()] });
    }
    if (calls.length === 2) {
      return response({ json: [] });
    }

    const inserted = JSON.parse(options.body);
    return response({ json: [{ ...inserted, created_at: createdAt }] });
  };

  const res = mockRes();
  await handler({ query: { tagId: " fur-000001 " } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "VERIFIED");
  assert.match(res.body.verificationId, /^VR-\d{8}-\d{6}-000001$/);
  assert.equal(res.body.verifiedAt, createdAt);
  assert.equal(calls[2].options.method, "POST");
  assert.match(calls[1].url, /verification_records/);
  assert.match(calls[1].url, /created_at/);
  assert.equal(JSON.parse(calls[2].options.body).created_at, undefined);
});

test("reuses the stored record on repeated verification", async () => {
  configureSupabase();
  const storedRecord = {
    verification_id: "VR-20260802-115641-000001",
    tag_id: "FUR-000001",
    created_at: "2026-08-02T11:56:41.000Z",
    status: "VERIFIED",
    product: "Bag",
    brand: "FUR"
  };
  let savedRecord;
  let insertCount = 0;

  global.fetch = async (url, options = {}) => {
    if (url.includes("/rest/v1/Products")) {
      return response({ json: [verifiedProduct()] });
    }

    if (options.method === "POST") {
      insertCount += 1;
      savedRecord = {
        ...JSON.parse(options.body),
        created_at: "2026-08-08T09:00:00.000Z"
      };
      return response({ json: [savedRecord] });
    }

    return response({ json: savedRecord ? [savedRecord] : [] });
  };

  const firstRes = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, firstRes);
  savedRecord = storedRecord;
  const secondRes = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, secondRes);

  assert.equal(insertCount, 1);
  assert.equal(secondRes.body.verificationId, storedRecord.verification_id);
  assert.equal(secondRes.body.verifiedAt, storedRecord.created_at);
});

test("reuses the winning record after a concurrent insert conflict", async () => {
  configureSupabase();
  const storedRecord = {
    verification_id: "VR-20260802-120000-000001",
    tag_id: "FUR-000001",
    created_at: "2026-08-02T12:00:00.000Z",
    status: "VERIFIED",
    product: "Bag",
    brand: "FUR"
  };
  let verificationLookups = 0;
  let insertCount = 0;

  global.fetch = async (url, options = {}) => {
    if (url.includes("/rest/v1/Products")) {
      return response({ json: [verifiedProduct()] });
    }

    if (options.method === "POST") {
      insertCount += 1;
      return response({ ok: false, status: 409, text: "duplicate key" });
    }

    verificationLookups += 1;
    return response({
      json: verificationLookups === 1 ? [] : [storedRecord]
    });
  };

  const res = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verificationId, storedRecord.verification_id);
  assert.equal(res.body.verifiedAt, storedRecord.created_at);
  assert.equal(insertCount, 1);
  assert.equal(verificationLookups, 2);
});

test("does not insert for unverified product", async () => {
  configureSupabase();
  let calls = 0;

  global.fetch = async () => {
    calls += 1;
    return response({
      json: [{ ...verifiedProduct(), status: "PENDING" }]
    });
  };

  const res = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "PENDING");
  assert.equal(calls, 1);
});

test("returns 502 when verification record insert fails", async () => {
  configureSupabase();
  let calls = 0;

  global.fetch = async () => {
    calls += 1;
    if (calls === 1) return response({ json: [verifiedProduct()] });
    if (calls === 2) return response({ json: [] });
    return response({ ok: false, status: 500, text: "insert failed" });
  };

  const res = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, res);

  assert.equal(res.statusCode, 502);
  assert.equal(res.body.message, "Verification record could not be saved");
});

test("rejects invalid tag format before calling Supabase", async () => {
  let called = false;
  global.fetch = async () => {
    called = true;
  };

  const res = mockRes();
  await handler({ query: { tagId: "bad" } }, res);

  assert.equal(res.statusCode, 400);
  assert.equal(called, false);
});

test("creates deterministic verification ID with supplied date", () => {
  assert.equal(
    createVerificationId("FUR-000123", new Date("2026-08-01T12:34:56.000Z")),
    "VR-20260801-123456-000123"
  );
});
