import { createHash, timingSafeEqual } from "node:crypto";

const ROLE_PERMISSIONS = Object.freeze({
  viewer: Object.freeze(["product:read", "activity:read"]),
  editor: Object.freeze(["product:read", "product:add", "product:update", "activity:read"]),
  administrator: Object.freeze([
    "product:read",
    "product:add",
    "product:update",
    "product:suspend",
    "activity:read"
  ])
});

const PRODUCT_STATUSES = new Set(["active", "suspended"]);
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,119}$/;
const SKU_PATTERN = /^[A-Z0-9][A-Z0-9._-]{1,63}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function adminSystemEnabled(env = process.env) {
  return env.ENABLE_ADMIN_SYSTEM === "true";
}

function permissionsFor(role) {
  return ROLE_PERMISSIONS[role] ?? Object.freeze([]);
}

function hasPermission(role, permission) {
  return permissionsFor(role).includes(permission);
}

function parsePrincipals(raw) {
  if (!raw) return [];
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(value) || value.length > 100) return [];
  const seen = new Set();
  const principals = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const id = String(entry.id ?? "").trim();
    const role = String(entry.role ?? "").trim();
    const tokenSha256 = String(entry.tokenSha256 ?? "").trim().toLowerCase();
    if (!ID_PATTERN.test(id) || !ROLE_PERMISSIONS[role] || !SHA256_PATTERN.test(tokenSha256) || seen.has(id)) return [];
    seen.add(id);
    principals.push(Object.freeze({ id, role, tokenSha256 }));
  }
  return principals;
}

function authenticateAdmin(header, principalsRaw) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  if (token.length < 32 || token.length > 512) return null;
  const supplied = Buffer.from(createHash("sha256").update(token, "utf8").digest("hex"));
  for (const principal of parsePrincipals(principalsRaw)) {
    const expected = Buffer.from(principal.tokenSha256);
    if (supplied.length === expected.length && timingSafeEqual(supplied, expected)) {
      return Object.freeze({ id: principal.id, role: principal.role });
    }
  }
  return null;
}

function normalizeProduct(input, operation) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, message: "A JSON product object is required" };
  }
  const allowed = operation === "add"
    ? new Set(["sku", "name", "description"])
    : new Set(["productId", "name", "description"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    return { ok: false, message: "Product contains unsupported fields" };
  }
  const name = String(input.name ?? "").trim();
  const description = input.description == null ? null : String(input.description).trim();
  if (name.length < 1 || name.length > 200) return { ok: false, message: "Invalid product name" };
  if (description !== null && description.length > 2000) return { ok: false, message: "Invalid product description" };
  if (operation === "add") {
    const sku = String(input.sku ?? "").trim().toUpperCase();
    if (!SKU_PATTERN.test(sku)) return { ok: false, message: "Invalid product SKU" };
    return { ok: true, value: { sku, name, description } };
  }
  const productId = String(input.productId ?? "").trim();
  if (!ID_PATTERN.test(productId)) return { ok: false, message: "Invalid productId" };
  return { ok: true, value: { productId, name, description } };
}

function normalizeSuspension(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, message: "A JSON suspension object is required" };
  }
  const allowed = new Set(["productId", "reason"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    return { ok: false, message: "Suspension contains unsupported fields" };
  }
  const productId = String(input.productId ?? "").trim();
  const reason = String(input.reason ?? "").trim();
  if (!ID_PATTERN.test(productId)) return { ok: false, message: "Invalid productId" };
  if (reason.length < 1 || reason.length > 500) return { ok: false, message: "Invalid suspension reason" };
  return { ok: true, value: { productId, reason, status: "suspended" } };
}

function validStatus(status) {
  return PRODUCT_STATUSES.has(status);
}

export {
  ROLE_PERMISSIONS,
  adminSystemEnabled,
  authenticateAdmin,
  hasPermission,
  normalizeProduct,
  normalizeSuspension,
  parsePrincipals,
  permissionsFor,
  validStatus
};
