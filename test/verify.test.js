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

test("persists and returns verification record", async () => {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
  const calls = [];

  global.fetch = async (url, options = {}) => {
    calls.push({ url, options });

    if (calls.length === 1) {
      return response({
        json: [
          {
            tag_id: "FUR-000001",
            product: "Bag",
            brand: "FUR",
            status: "VERIFIED"
          }
        ]
      });
    }

    const inserted = JSON.parse(options.body);
    return response({ json: [inserted] });
  };

  const res = mockRes();
  await handler({ query: { tagId: " fur-000001 " } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "VERIFIED");
  assert.match(res.body.verificationId, /^VR-\d{8}-\d{6}-000001$/);
  assert.equal(calls[1].options.method, "POST");
  assert.match(calls[1].url, /verification_records/);
});

test("does not insert for unverified product", async () => {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
  let calls = 0;

  global.fetch = async () => {
    calls += 1;
    return response({
      json: [
        {
          tag_id: "FUR-000001",
          product: "Bag",
          brand: "FUR",
          status: "PENDING"
        }
      ]
    });
  };

  const res = mockRes();
  await handler({ query: { tagId: "FUR-000001" } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "PENDING");
  assert.equal(calls, 1);
});

test("returns 502 when verification record insert fails", async () => {
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "secret";
  let calls = 0;

  global.fetch = async () => {
    calls += 1;

    if (calls === 1) {
      return response({
        json: [
          {
            tag_id: "FUR-000001",
            product: "Bag",
            brand: "FUR",
            status: "VERIFIED"
          }
        ]
      });
    }

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
