import { randomUUID } from "node:crypto";
import {
  adminSystemEnabled,
  authenticateAdmin,
  hasPermission,
  normalizeProduct,
  normalizeSuspension
} from "./admin-foundation.js";

const OPERATIONS = Object.freeze({
  add: "product:add",
  update: "product:update",
  suspend: "product:suspend"
});

function validateRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, message: "A JSON administration request is required" };
  }
  const allowed = new Set(["operation", "product"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    return { ok: false, message: "Administration request contains unsupported fields" };
  }
  const operation = String(input.operation ?? "").trim().toLowerCase();
  if (!OPERATIONS[operation]) return { ok: false, message: "Invalid administration operation" };
  const product = operation === "suspend"
    ? normalizeSuspension(input.product)
    : normalizeProduct(input.product, operation);
  if (!product.ok) return product;
  return { ok: true, value: { operation, product: product.value } };
}

export default async function handler(req, res) {
  const requestId = randomUUID();
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (!adminSystemEnabled()) {
    return res.status(404).json({ ok: false, requestId, message: "Not found" });
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, requestId, message: "Method not allowed" });
  }

  const principal = authenticateAdmin(req.headers?.authorization, process.env.ADMIN_PRINCIPALS_JSON);
  if (!principal) return res.status(401).json({ ok: false, requestId, message: "Unauthorized" });

  const validated = validateRequest(req.body);
  if (!validated.ok) return res.status(400).json({ ok: false, requestId, message: validated.message });
  const permission = OPERATIONS[validated.value.operation];
  if (!hasPermission(principal.role, permission)) {
    return res.status(403).json({ ok: false, requestId, message: "Forbidden" });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(503).json({ ok: false, requestId, message: "Administration service unavailable" });
  }

  const { operation, product } = validated.value;
  const response = await fetch(`${supabaseUrl}/rest/v1/rpc/admin_mutate_product`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${supabaseSecretKey}`,
      apikey: supabaseSecretKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      p_operation: operation,
      p_actor_id: principal.id,
      p_actor_role: principal.role,
      p_product_id: product.productId ?? null,
      p_sku: product.sku ?? null,
      p_name: product.name ?? null,
      p_description: product.description ?? null,
      p_reason: product.reason ?? null
    })
  });

  if (!response.ok) {
    console.error("Administration product mutation failed", response.status, requestId);
    return res.status(502).json({ ok: false, requestId, message: "Product change was not recorded" });
  }
  const record = await response.json();
  return res.status(operation === "add" ? 201 : 200).json({ ok: true, requestId, product: record });
}

export { OPERATIONS, validateRequest };
