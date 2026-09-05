import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { afterEach } from "node:test";
import handler, { validateRequest } from "../api/admin-products.js";

const token = "test-token-that-is-at-least-thirty-two-bytes";
const tokenSha256 = createHash("sha256").update(token).digest("hex");
const originalFetch = global.fetch;

function mockResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }
  };
}

function enable(role = "administrator") {
  process.env.ENABLE_ADMIN_SYSTEM = "true";
  process.env.ADMIN_PRINCIPALS_JSON = JSON.stringify([{ id: "admin@example.com", role, tokenSha256 }]);
}

afterEach(() => {
  delete process.env.ENABLE_ADMIN_SYSTEM;
  delete process.env.ADMIN_PRINCIPALS_JSON;
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;
  global.fetch = originalFetch;
});

test("administration handler is disabled by default and performs no fetch", async () => {
  global.fetch = async () => assert.fail("fetch must not run");
  const res = mockResponse();
  await handler({ method: "POST", headers: {}, body: {} }, res);
  assert.equal(res.statusCode, 404);
  assert.equal(res.headers["Cache-Control"], "no-store");
});

test("enabled handler requires a valid hashed bearer credential", async () => {
  enable();
  const res = mockResponse();
  await handler({ method: "POST", headers: { authorization: "Bearer wrong-token-that-is-at-least-thirty-two" }, body: {} }, res);
  assert.equal(res.statusCode, 401);
});

test("permission levels prevent editors from suspending products", async () => {
  enable("editor");
  const res = mockResponse();
  await handler({
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: { operation: "suspend", product: { productId: "prod-1", reason: "Recall" } }
  }, res);
  assert.equal(res.statusCode, 403);
});

test("validated additions call only the transactional RPC", async () => {
  enable("editor");
  process.env.SUPABASE_URL = "https://example.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "server-secret";
  let call;
  global.fetch = async (url, options) => {
    call = { url, options };
    return { ok: true, status: 200, json: async () => ({ product_id: "prod-1", status: "active" }) };
  };
  const res = mockResponse();
  await handler({
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: { operation: "add", product: { sku: "fur-001", name: "Coat" } }
  }, res);
  assert.equal(res.statusCode, 201);
  assert.equal(call.url, "https://example.supabase.co/rest/v1/rpc/admin_mutate_product");
  const rpc = JSON.parse(call.options.body);
  assert.equal(rpc.p_actor_id, "admin@example.com");
  assert.equal(rpc.p_actor_role, "editor");
  assert.equal(rpc.p_sku, "FUR-001");
  assert.equal(rpc.p_operation, "add");
});

test("request validation rejects unknown operations and fields", () => {
  assert.equal(validateRequest({ operation: "delete", product: {} }).ok, false);
  assert.equal(validateRequest({ operation: "add", product: { sku: "FUR-001", name: "Coat" }, extra: true }).ok, false);
});
