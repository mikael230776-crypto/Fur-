import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  adminSystemEnabled,
  authenticateAdmin,
  hasPermission,
  normalizeProduct,
  normalizeSuspension,
  parsePrincipals
} from "../api/admin-foundation.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");

test("administration is disabled by default", () => {
  assert.equal(adminSystemEnabled({}), false);
  assert.equal(adminSystemEnabled({ ENABLE_ADMIN_SYSTEM: "TRUE" }), false);
  assert.equal(adminSystemEnabled({ ENABLE_ADMIN_SYSTEM: "true" }), true);
});

test("roles deny permissions they do not own", () => {
  assert.equal(hasPermission("viewer", "product:read"), true);
  assert.equal(hasPermission("viewer", "product:add"), false);
  assert.equal(hasPermission("editor", "product:update"), true);
  assert.equal(hasPermission("editor", "product:suspend"), false);
  assert.equal(hasPermission("administrator", "product:suspend"), true);
  assert.equal(hasPermission("unknown", "product:read"), false);
});

test("authentication uses stored token hashes", () => {
  const token = "a-secure-test-token-that-is-longer-than-32-bytes";
  const principals = JSON.stringify([{ id: "admin@example.com", role: "administrator", tokenSha256: hash(token) }]);
  assert.deepEqual(authenticateAdmin(`Bearer ${token}`, principals), { id: "admin@example.com", role: "administrator" });
  assert.equal(authenticateAdmin("Bearer wrong-token-that-is-longer-than-32-bytes", principals), null);
  assert.equal(authenticateAdmin(token, principals), null);
});

test("invalid principal configuration fails closed", () => {
  assert.deepEqual(parsePrincipals("not-json"), []);
  assert.deepEqual(parsePrincipals(JSON.stringify([{ id: "a", role: "owner", tokenSha256: "0".repeat(64) }])), []);
  assert.equal(authenticateAdmin("Bearer a-secure-test-token-that-is-longer-than-32-bytes", "not-json"), null);
});

test("validates and normalizes product additions", () => {
  assert.deepEqual(normalizeProduct({ sku: " fur-001 ", name: " Coat ", description: null }, "add"), {
    ok: true,
    value: { sku: "FUR-001", name: "Coat", description: null }
  });
  assert.equal(normalizeProduct({ sku: "x", name: "Coat" }, "add").ok, false);
  assert.equal(normalizeProduct({ sku: "FUR-001", name: "Coat", status: "active" }, "add").ok, false);
});

test("validates updates and suspensions", () => {
  assert.equal(normalizeProduct({ productId: "prod-1", name: "Updated" }, "update").ok, true);
  assert.equal(normalizeSuspension({ productId: "prod-1", reason: "Recall" }).ok, true);
  assert.equal(normalizeSuspension({ productId: "prod-1", reason: "" }).ok, false);
  assert.equal(normalizeSuspension({ productId: "prod-1", reason: "Recall", status: "suspended" }).ok, false);
});
