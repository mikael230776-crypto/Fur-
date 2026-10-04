import { randomUUID } from "node:crypto";

const GTIN_PATTERN = /^\d{14}$/;
const SERIAL_PATTERN = /^[A-Za-z0-9._-]{1,20}$/;

function sendError(res, status, code, message, requestId) {
  return res.status(status).json({
    ok: false,
    error: {
      code,
      message,
      requestId,
    },
  });
}

function getSupabaseConfig() {
  const url = String(process.env.SUPABASE_URL || "")
    .trim()
    .replace(/\/+$/, "");

  const secret =
    process.env.SUPABASE_SECRET ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_SECRET ||
    "";

  return {
    url,
    secret: String(secret).trim(),
  };
}

function getSupabaseHeaders(secret) {
  const headers = {
    apikey: secret,
    Accept: "application/json",
  };

  if (secret.startsWith("eyJ")) {
    headers.Authorization = `Bearer ${secret}`;
  }

  return headers;
}

async function readSupabase(url, secret, query) {
  const response = await fetch(`${url}/rest/v1/${query}`, {
    method: "GET",
    headers: getSupabaseHeaders(secret),
  });

  if (!response.ok) {
    throw new Error("Supabase source request failed");
  }

  return response.json();
}

export default async function handler(req, res) {
  const requestId = randomUUID();

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");

    return sendError(
      res,
      405,
      "METHOD_NOT_ALLOWED",
      "Only GET is supported",
      requestId
    );
  }

  const accept = String(req.headers?.accept || "");

  if (
    accept &&
    !accept.includes("*/*") &&
    !accept.includes("application/json")
  ) {
    return sendError(
      res,
      406,
      "NOT_ACCEPTABLE",
      "Only application/json is supported",
      requestId
    );
  }

  const gtin = String(req.query?.gtin ?? "").trim();
  const serialNumber = String(req.query?.serialNumber ?? "").trim();

  if (!GTIN_PATTERN.test(gtin)) {
    return sendError(
      res,
      400,
      "INVALID_GTIN",
      "GTIN must be exactly 14 digits",
      requestId
    );
  }

  if (!SERIAL_PATTERN.test(serialNumber)) {
    return sendError(
      res,
      400,
      "INVALID_SERIAL",
      "Serial number is invalid",
      requestId
    );
  }

  const { url, secret } = getSupabaseConfig();

  if (!url || !secret) {
    return sendError(
      res,
      500,
      "DPP_CONFIGURATION_ERROR",
      "DPP service is not configured",
      requestId
    );
  }

  try {
    const passportRows = await readSupabase(
      url,
      secret,
      `dpp_passports?select=gtin,serial_number,fur_tag_id,passport_version,passport_lifecycle_status,created_at,last_updated_at&gtin=eq.${encodeURIComponent(
        gtin
      )}&serial_number=eq.${encodeURIComponent(
        serialNumber
      )}&passport_lifecycle_status=neq.DRAFT&limit=1`
    );

    const passport = passportRows?.[0];

    if (!passport) {
      return sendError(
        res,
        404,
        "PASSPORT_NOT_FOUND",
        "No public DPP passport exists for this identifier",
        requestId
      );
     }

    const productRows = await readSupabase(
      url,
      secret,
      `Products?select=product,brand,status&tag_id=eq.${encodeURIComponent(
        passport.fur_tag_id
      )}&limit=1`
    );

    const product = productRows?.[0];

    if (!product) {
      return sendError(
        res,
        502,
        "REGISTRY_RECORD_UNAVAILABLE",
        "The authoritative Registry record is unavailable",
        requestId
      );
    }

    const passportId =
      `https://furfreedomunityrespect.com/01/${gtin}/21/` +
      encodeURIComponent(serialNumber);

    return res.status(200).json({
      passportId,

      identifier: {
        gtin,
        serialNumber,
      },

      product: {
        name: product.product,
        brand: product.brand,
      },

      verification: {
        status: product.status,
      },

      metadata: {
        schemaVersion: "1.0",
        passportVersion: passport.passport_version,
        passportLifecycleStatus: passport.passport_lifecycle_status,
        createdAt: passport.created_at,
        lastUpdatedAt: passport.last_updated_at,
      },
    });
  } catch {
    return sendError(
      res,
      502,
      "DPP_SOURCE_UNAVAILABLE",
      "The DPP source is temporarily unavailable",
      requestId
    );
  }
}
