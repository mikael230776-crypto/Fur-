import { randomUUID } from "node:crypto";

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const rateLimitStore =
  globalThis.__furVerificationRateLimits ??
  (globalThis.__furVerificationRateLimits = new Map());

function getClientIp(req) {
  const forwarded = req.headers?.["x-forwarded-for"];
  const firstForwarded =
    typeof forwarded === "string" ? forwarded.split(",")[0].trim() : null;

  return firstForwarded || req.socket?.remoteAddress || "unknown";
}

function checkRateLimit(req, now = Date.now()) {
  const clientIp = getClientIp(req);
  const current = rateLimitStore.get(clientIp);

  if (!current || now - current.startedAt >= RATE_LIMIT_WINDOW_MS) {
    rateLimitStore.set(clientIp, { count: 1, startedAt: now });
    return {
      allowed: true,
      remaining: RATE_LIMIT_MAX_REQUESTS - 1,
      retryAfter: 0
    };
  }

  current.count += 1;
  const retryAfter = Math.max(
    1,
    Math.ceil((RATE_LIMIT_WINDOW_MS - (now - current.startedAt)) / 1000)
  );

  return {
    allowed: current.count <= RATE_LIMIT_MAX_REQUESTS,
    remaining: Math.max(0, RATE_LIMIT_MAX_REQUESTS - current.count),
    retryAfter
  };
}

function resetRateLimits() {
  rateLimitStore.clear();
}

function buildResponse(status, extras = {}) {
  return {
    status,
    ...extras
  };
}

function createVerificationId(tagId, now = new Date()) {
  const date = now.toISOString().slice(0, 10).replaceAll("-", "");
  const time = now.toISOString().slice(11, 19).replaceAll(":", "");
  const tagSuffix = tagId.replace(/[^0-9]/g, "").slice(-6).padStart(6, "0");
  return `VR-${date}-${time}-${tagSuffix}`;
}

function supabaseHeaders(supabaseSecretKey, extras = {}) {
  return {
    apikey: supabaseSecretKey,
    Authorization: `Bearer ${supabaseSecretKey}`,
    Accept: "application/json",
    ...extras
  };
}

export default async function handler(req, res) {
  const requestId = randomUUID();
  const startedAt = Date.now();
  const method = (req.method || "GET").toUpperCase();
  let loggedTagId = null;

  res.setHeader?.("Cache-Control", "no-store");
  res.setHeader?.("X-Request-ID", requestId);
  res.on?.("finish", () => {
    console.info(
      JSON.stringify({
        event: "verification_request",
        requestId,
        method,
        statusCode: res.statusCode,
        durationMs: Date.now() - startedAt,
        tagId: loggedTagId
      })
    );
  });

  if (method !== "GET") {
    res.setHeader?.("Allow", "GET");
    return res.status(405).json(
      buildResponse("ERROR", {
        message: "Method not allowed"
      })
    );
  }

  const rateLimit = checkRateLimit(req);
  res.setHeader?.("X-RateLimit-Limit", String(RATE_LIMIT_MAX_REQUESTS));
  res.setHeader?.("X-RateLimit-Remaining", String(rateLimit.remaining));

  if (!rateLimit.allowed) {
    res.setHeader?.("Retry-After", String(rateLimit.retryAfter));
    return res.status(429).json(
      buildResponse("ERROR", {
        message: "Too many verification requests. Please try again shortly."
      })
    );
  }

  const rawTagId = req.query?.tagId;
  const tagId =
    typeof rawTagId === "string" ? rawTagId.trim().toUpperCase() : rawTagId;
  loggedTagId = typeof tagId === "string" ? tagId : null;

  if (!tagId) {
    return res.status(400).json(
      buildResponse("ERROR", {
        message: "Missing tagId"
      })
    );
  }

  if (!/^FUR-\d{6}$/.test(tagId)) {
    return res.status(400).json(
      buildResponse("ERROR", {
        message: "Invalid tagId format"
      })
    );
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json(
      buildResponse("ERROR", {
        message: "Supabase environment variables are missing"
      })
    );
  }

  try {
    const productEndpoint =
      `${supabaseUrl}/rest/v1/Products` +
      `?tag_id=eq.${encodeURIComponent(tagId)}` +
      `&select=tag_id,product,brand,status` +
      `&limit=1`;

    const productResponse = await fetch(productEndpoint, {
      headers: supabaseHeaders(supabaseSecretKey)
    });

    if (!productResponse.ok) {
      const errorText = await productResponse.text();
      console.error("Supabase query failed:", productResponse.status, errorText);
      return res.status(502).json(
        buildResponse("ERROR", {
          message: "Registry lookup failed"
        })
      );
    }

    const rows = await productResponse.json();
    const product = rows[0];

    if (!product) {
      return res.status(404).json(
        buildResponse("NOT_VERIFIED", {
          tagId,
          message: "Product not found"
        })
      );
    }

    if (product.status !== "VERIFIED") {
      return res.status(200).json(
        buildResponse(product.status || "NOT_VERIFIED", {
          tagId: product.tag_id,
          product: product.product,
          brand: product.brand,
          message: "Product record is not currently verified"
        })
      );
    }

    const verificationLookupEndpoint =
      `${supabaseUrl}/rest/v1/verification_records` +
      `?tag_id=eq.${encodeURIComponent(product.tag_id)}` +
      `&select=verification_id,tag_id,created_at,status,product,brand` +
      `&order=created_at.asc` +
      `&limit=1`;

    const lookupResponse = await fetch(verificationLookupEndpoint, {
      headers: supabaseHeaders(supabaseSecretKey)
    });

    if (!lookupResponse.ok) {
      const errorText = await lookupResponse.text();
      console.error(
        "Supabase verification record lookup failed:",
        lookupResponse.status,
        errorText
      );
      return res.status(502).json(
        buildResponse("ERROR", {
          message: "Verification record could not be loaded"
        })
      );
    }

    const existingRecords = await lookupResponse.json();
    let savedRecord = existingRecords[0];

    if (!savedRecord) {
      const verificationRecord = {
        verification_id: createVerificationId(product.tag_id),
        tag_id: product.tag_id,
        status: product.status,
        product: product.product,
        brand: product.brand
      };
      const verificationEndpoint =
        `${supabaseUrl}/rest/v1/verification_records` +
        `?select=verification_id,tag_id,created_at,status,product,brand`;

      const verificationResponse = await fetch(verificationEndpoint, {
        method: "POST",
        headers: supabaseHeaders(supabaseSecretKey, {
          "Content-Type": "application/json",
          Prefer: "return=representation"
        }),
        body: JSON.stringify(verificationRecord)
      });

      if (!verificationResponse.ok) {
        const errorText = await verificationResponse.text();

        if (verificationResponse.status === 409) {
          const conflictLookupResponse = await fetch(verificationLookupEndpoint, {
            headers: supabaseHeaders(supabaseSecretKey)
          });

          if (conflictLookupResponse.ok) {
            const conflictRecords = await conflictLookupResponse.json();
            savedRecord = conflictRecords[0];
          }
        }

        if (!savedRecord) {
          console.error(
            "Supabase verification record insert failed:",
            verificationResponse.status,
            errorText
          );
          return res.status(502).json(
            buildResponse("ERROR", {
              message: "Verification record could not be saved"
            })
          );
        }
      } else {
        const savedRecords = await verificationResponse.json();
        savedRecord = savedRecords[0];
      }

      if (!savedRecord) {
        console.error("Supabase verification record insert returned no record");
        return res.status(502).json(
          buildResponse("ERROR", {
            message: "Verification record could not be saved"
          })
        );
      }
    }

    return res.status(200).json(
      buildResponse("VERIFIED", {
        tagId: savedRecord.tag_id,
        product: savedRecord.product ?? product.product,
        brand: savedRecord.brand ?? product.brand,
        verificationId: savedRecord.verification_id,
        verifiedAt: savedRecord.created_at
      })
    );
  } catch (error) {
    console.error("Verification API error:", error);
    return res.status(500).json(
      buildResponse("ERROR", {
        message: "Verification service is temporarily unavailable"
      })
    );
  }
}

export {
  buildResponse,
  checkRateLimit,
  createVerificationId,
  resetRateLimits,
  supabaseHeaders
};
