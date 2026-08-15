import test from "node:test";
import assert from "node:assert/strict";
import handler, {
  checkRateLimit,
  createVerificationId,
  resetRateLimits,
  saveVerificationScan,
  scanHistoryEnabled
} from "../api/verify.js";

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
  delete process.env.ENABLE_SCAN_HISTORY;
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
  assert.match(
    res.body.verificationId,
    /^VR-\d{8}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  );
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

test("creates verification ID with date and unpredictable UUID", () => {
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  assert.equal(
    createVerificationId(new Date("2026-08-01T12:34:56.000Z"), uuid),
    `VR-20260801-${uuid}`
  );
});

test("creates different verification IDs for the same date", () => {
  const first = createVerificationId(new Date("2026-08-01T12:34:56.000Z"));
  const second = createVerificationId(new Date("2026-08-01T12:34:56.000Z"));

  assert.notEqual(first, second);
});

test("limits repeated requests from the same visitor", () => {
  resetRateLimits();
  const req = {
    headers: { "x-forwarded-for": "203.0.113.10" }
  };

  for (let count = 0; count < 30; count += 1) {
    assert.equal(checkRateLimit(req, 1_000).allowed, true);
  }

  const blocked = checkRateLimit(req, 1_000);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.remaining, 0);
  assert.equal(blocked.retryAfter, 60);

  const differentVisitor = checkRateLimit(
    { headers: { "x-forwarded-for": "203.0.113.11" } },
    1_000
  );
  assert.equal(differentVisitor.allowed, true);
});

test("allows requests again after the rate-limit window", () => {
  resetRateLimits();
  const req = {
    headers: { "x-forwarded-for": "203.0.113.12" }
  };

  for (let count = 0; count < 30; count += 1) {
    checkRateLimit(req, 1_000);
  }

  assert.equal(checkRateLimit(req, 1_000).allowed, false);
  assert.equal(checkRateLimit(req, 61_000).allowed, true);
});

test("rejects non-GET verification requests", async () => {
  resetRateLimits();
  const res = mockRes();
  res.headers = {};
  res.setHeader = function setHeader(name, value) {
    this.headers[name] = value;
  };

  await handler(
    {
      method: "POST",
      headers: { "x-forwarded-for": "203.0.113.13" },
      query: { tagId: "FUR-000001" }
    },
    res
  );

  assert.equal(res.statusCode, 405);
  assert.equal(res.body.status, "ERROR");
  assert.equal(res.body.message, "Method not allowed");
  assert.equal(res.headers.Allow, "GET");
});

test("logs the request outcome without logging the visitor IP", async () => {
  resetRateLimits();
  configureSupabase();

  let finishHandler;
  const messages = [];
  const originalInfo = console.info;

  global.fetch = async (url) => {
    if (url.includes("/rest/v1/Products")) {
      return response({ json: [] });
    }
    return response({ json: [] });
  };

  const res = mockRes();
  res.headers = {};
  res.setHeader = function setHeader(name, value) {
    this.headers[name] = value;
  };
  res.on = function on(event, listener) {
    if (event === "finish") finishHandler = listener;
  };

  console.info = (message) => messages.push(message);

  try {
    await handler(
      {
        method: "GET",
        headers: { "x-forwarded-for": "203.0.113.14" },
        query: { tagId: "FUR-999999" }
      },
      res
    );
    finishHandler();
  } finally {
    console.info = originalInfo;
  }

  assert.equal(res.statusCode, 404);
  assert.match(res.headers["X-Request-ID"], /^[0-9a-f-]{36}$/i);

  const log = JSON.parse(messages[0]);
  assert.equal(log.event, "verification_request");
  assert.equal(log.method, "GET");
  assert.equal(log.statusCode, 404);
  assert.equal(log.tagId, undefined);
  assert.equal(log.tagState, "valid");
  assert.equal(JSON.stringify(log).includes("203.0.113.14"), false);
});

test("scan history is disabled unless explicitly enabled", () => {
  delete process.env.ENABLE_SCAN_HISTORY;
  assert.equal(scanHistoryEnabled(), false);
  process.env.ENABLE_SCAN_HISTORY = "true";
  assert.equal(scanHistoryEnabled(), true);
  delete process.env.ENABLE_SCAN_HISTORY;
});

test("saves privacy-safe NFC scan history", async () => {
  const calls = [];
  global.fetch = async (url, options = {}) => {
    calls.push({ url, options });
    return response({ status: 201 });
  };

  const saved = await saveVerificationScan(
    "https://example.supabase.co",
    "secret",
    {
      tagId: "FUR-000001",
      requestId: "2b9a81ee-3c1f-4f3c-9b74-a1551a54d3ce",
      resultStatus: "VERIFIED"
    }
  );

  assert.equal(saved, true);
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /verification_scans$/);
  assert.equal(calls[0].options.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    tag_id: "FUR-000001",
    request_id: "2b9a81ee-3c1f-4f3c-9b74-a1551a54d3ce",
    result_status: "VERIFIED",
security_flag: null
  });
  assert.equal(JSON.stringify(calls[0]).includes("203.0.113"), false);
});

test("reports scan history storage failure", async () => {
  global.fetch = async () =>
    response({ ok: false, status: 500, text: "insert failed" });

  const originalError = console.error;
  console.error = () => {};
  try {
    assert.equal(
      await saveVerificationScan(
        "https://example.supabase.co",
        "secret",
        {
          tagId: "FUR-000001",
          requestId: "78fceff4-905b-45fd-8b45-54c7e9471590",
          resultStatus: "VERIFIED"
        }
      ),
      false
    );
  } finally {
    console.error = originalError;
  }
});
