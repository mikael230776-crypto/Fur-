import { randomUUID } from "node:crypto";

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const REPEATED_SCAN_WINDOW_MS = 60_000;
const REPEATED_SCAN_THRESHOLD = 5;
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

function createVerificationId(now = new Date(), uuid = randomUUID()) {
  const date = now.toISOString().slice(0, 10).replaceAll("-", "");
  return `VR-${date}-${uuid}`;
}

function getTagLogState(tagId) {
  if (!tagId) return "missing";
  return /^FUR-\d{6}$/.test(tagId) ? "valid" : "invalid";
}

function scanHistoryEnabled() {
  return process.env.ENABLE_SCAN_HISTORY === "true";
}

function supabaseHeaders(supabaseSecretKey, extras = {}) {
  return {
    apikey: supabaseSecretKey,
    Authorization: `Bearer ${supabaseSecretKey}`,
    Accept: "application/json",
    ...extras
  };
}
async function getRecentVerificationScans(
  supabaseUrl,
  supabaseSecretKey,
  tagId,
  now = Date.now()
) {
  const since = new Date(now - REPEATED_SCAN_WINDOW_MS).toISOString();

  const endpoint =
    `${supabaseUrl}/rest/v1/verification_scans` +
    `?tag_id=eq.${encodeURIComponent(tagId)}` +
    `&scanned_at=gte.${encodeURIComponent(since)}` +
    `&select=tag_id,scanned_at` +
    `&order=scanned_at.desc`;

  const response = await fetch(endpoint, {
    headers: supabaseHeaders(supabaseSecretKey)
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error(
      "Supabase scan history lookup failed:",
      response.status,
      errorText
    );
    return null;
  }

  return response.json();
}
async function saveVerificationScan(
  supabaseUrl,
  supabaseSecretKey,
  { tagId, requestId, resultStatus }
) {
  const endpoint = `${supabaseUrl}/rest/v1/verification_scans`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: supabaseHeaders(supabaseSecretKey, {
      "Content-Type": "application/json",
      Prefer: "return=minimal"
    }),
    body: JSON.stringify({
      tag_id: tagId,
      request_id: requestId,
      result_status: resultStatus
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error("Supabase scan history insert failed:", response.status, errorText);
    return false;
  }

  return true;
}

export default async function handler(req, res) {
  const requestId = randomUUID();
  const startedAt = Date.now();
  const method = (req.method || "GET").toUpperCase();
  let tagState = "missing";

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
        tagState
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
  tagState = getTagLogState(tagId);

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

  async function recordScan(resultStatus) {
  if (!scanHistoryEnabled()) return true;

  const recentScans = await getRecentVerificationScans(
    supabaseUrl,
    supabaseSecretKey,
    tagId
  );

  if (Array.isArray(recentScans) &&
      recentScans.length >= REPEATED_SCAN_THRESHOLD) {
    console.warn("Suspicious repeated NFC tag scans detected");
  }

  return saveVerificationScan(supabaseUrl, supabaseSecretKey, {
    tagId,
    requestId,
    resultStatus
  });
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
      if (!(await recordScan("NOT_VERIFIED"))) {
        return res.status(502).json(
          buildResponse("ERROR", {
            message: "Scan history could not be saved"
          })
        );
      }

      return res.status(404).json(
        buildResponse("NOT_VERIFIED", {
          tagId,
          message: "Product not found"
        })
      );
    }

    if (product.status !== "VERIFIED") {
      const resultStatus = product.status || "NOT_VERIFIED";
      if (!(await recordScan(resultStatus))) {
        return res.status(502).json(
          buildResponse("ERROR", {
            message: "Scan history could not be saved"
          })
        );
      }

      return res.status(200).json(
        buildResponse(resultStatus, {
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
        verification_id: createVerificationId(),
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

    if (!(await recordScan("VERIFIED"))) {
      return res.status(502).json(
        buildResponse("ERROR", {
          message: "Scan history could not be saved"
        })
      );
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
  getTagLogState,
  resetRateLimits,
  saveVerificationScan,
  scanHistoryEnabled,
  supabaseHeaders
};
