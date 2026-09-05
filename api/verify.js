import { randomUUID } from "node:crypto";
import { aesCmac, hexToBuffer, secureEqual, truncateSdmMac } from "./sun-crypto.js";
import { getPhysicalAuthSummary, physicalAuthEnabled } from "./physical-auth.js";

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

function sunValidationEnabled() {
  return process.env.ENABLE_SUN_VALIDATION === "true";
}

function normaliseUid(value) {
  return typeof value === "string"
    ? value.replace(/[^0-9a-f]/gi, "").toUpperCase()
    : "";
}

function validateSunMac(uidHex, counterHex, macHex, keyHex) {
  const key = hexToBuffer(keyHex, 16);
  const uid = hexToBuffer(uidHex, 7);
  const counter = hexToBuffer(counterHex, 3);
  const receivedMac = hexToBuffer(macHex, 8);
  const sessionVector = Buffer.concat([
    Buffer.from("3cc300010080", "hex"),
    uid,
    counter
  ]);
  const sessionKey = aesCmac(key, sessionVector);
  const expectedMac = truncateSdmMac(aesCmac(sessionKey, Buffer.alloc(0)));

  return secureEqual(expectedMac, receivedMac);
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
  { tagId, requestId, resultStatus, securityFlag = null }
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
      result_status: resultStatus,
      security_flag: securityFlag
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
  const sunSdmFileReadKey = process.env.SUN_SDM_FILE_READ_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json(
      buildResponse("ERROR", {
        message: "Supabase environment variables are missing"
      })
    );
  }

  let authenticatedUid = null;
  if (sunValidationEnabled()) {
    const uid = normaliseUid(req.query?.uid);
    const counter = req.query?.ctr;
    const mac = req.query?.cmac;

    if (!sunSdmFileReadKey) {
      return res.status(500).json(
        buildResponse("ERROR", { message: "SUN validation key is missing" })
      );
    }

    if (!uid || typeof counter !== "string" || typeof mac !== "string") {
      return res.status(400).json(
        buildResponse("ERROR", { message: "Missing SUN authentication data" })
      );
    }

    try {
      if (!validateSunMac(uid, counter, mac, sunSdmFileReadKey)) {
        return res.status(403).json(
          buildResponse("NOT_VERIFIED", {
            tagId,
            message: "SUN authentication failed"
          })
        );
      }
    } catch {
      return res.status(400).json(
        buildResponse("ERROR", { message: "Invalid SUN authentication data" })
      );
    }

    authenticatedUid = uid;
  }
let repeatedScanDetected = false;
  async function recordScan(resultStatus) {
  if (!scanHistoryEnabled()) return true;

  const recentScans = await getRecentVerificationScans(
    supabaseUrl,
    supabaseSecretKey,
    tagId
  );

  if (Array.isArray(recentScans) &&
      recentScans.length + 1 >= REPEATED_SCAN_THRESHOLD) {
   repeatedScanDetected = true;
    console.warn("Suspicious repeated NFC tag scans detected");
  }

  const securityFlag = repeatedScanDetected ? "REPEATED_SCAN" : null;

  return saveVerificationScan(supabaseUrl, supabaseSecretKey, {
    tagId,
    requestId,
    resultStatus,
    securityFlag
  });
      
}

try {
   const nfcTagEndpoint =
    `${supabaseUrl}/rest/v1/nfc_tags` +
    `?tag_id=eq.${encodeURIComponent(tagId)}` +
    `&select=tag_id,tag_uid,status` +
    `&limit=1`;

  const nfcTagResponse = await fetch(nfcTagEndpoint, {
    headers: supabaseHeaders(supabaseSecretKey)
  });

  if (!nfcTagResponse.ok) {
    const errorText = await nfcTagResponse.text();
    console.error(
      "NFC tag registry lookup failed:",
      nfcTagResponse.status,
      errorText
    );

    return res.status(502).json(
      buildResponse("ERROR", {
        message: "NFC tag registry lookup failed"
      })
    );
  }

  const nfcTags = await nfcTagResponse.json();
  const nfcTag = nfcTags[0];

  if (!nfcTag) {
    return res.status(404).json(
      buildResponse("NOT_VERIFIED", {
        tagId,
        message: "NFC tag is not registered"
      })
    );
  }

  if (
    authenticatedUid &&
    normaliseUid(nfcTag.tag_uid) !== authenticatedUid
  ) {
    return res.status(403).json(
      buildResponse("NOT_VERIFIED", {
        tagId,
        message: "Authenticated UID does not match the registered NFC tag"
      })
    );
  }

  if (nfcTag.status !== "ACTIVE") {
    const resultStatus = ["SUSPENDED", "REPLACED"].includes(nfcTag.status)
      ? nfcTag.status
      : "NOT_VERIFIED";

    return res.status(403).json(
      buildResponse(resultStatus, {
        tagId,
        message: "NFC tag is not active"
      })
    );
  }
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

      const responseStatus = ["SUSPENDED", "REPLACED"].includes(resultStatus) ? 403 : 200;

return res.status(responseStatus).json(
        buildResponse(resultStatus, {
          tagId: product.tag_id,
          product: product.product,
          brand: product.brand,
          message: "Product record is not currently verified"
        })
      );
    }

    let physicalAuthentication = { required: false, status: "NOT_REQUIRED" };
    if (physicalAuthEnabled()) {
      const physicalAuthResult = await getPhysicalAuthSummary(
        supabaseUrl,
        supabaseSecretKey,
        tagId,
        supabaseHeaders(supabaseSecretKey)
      );

      if (!physicalAuthResult.ok) {
        return res.status(502).json(
          buildResponse("ERROR", { message: physicalAuthResult.message })
        );
      }

      physicalAuthentication = physicalAuthResult.summary;

      if (physicalAuthentication.status === "FAILED") {
        if (!(await recordScan("NOT_VERIFIED"))) {
          return res.status(502).json(
            buildResponse("ERROR", { message: "Scan history could not be saved" })
          );
        }
        return res.status(403).json(
          buildResponse("NOT_VERIFIED", {
            tagId,
            product: product.product,
            brand: product.brand,
            physicalAuthentication,
            message: "Physical authentication failed"
          })
        );
      }

      if (["NOT_INSPECTED", "REVIEW_REQUIRED"].includes(physicalAuthentication.status)) {
        const resultStatus = physicalAuthentication.status === "NOT_INSPECTED"
          ? "PHYSICAL_CHECK_REQUIRED"
          : "REVIEW_REQUIRED";
        if (!(await recordScan(resultStatus))) {
          return res.status(502).json(
            buildResponse("ERROR", { message: "Scan history could not be saved" })
          );
        }
        return res.status(200).json(
          buildResponse(resultStatus, {
            tagId,
            product: product.product,
            brand: product.brand,
            physicalAuthentication,
            message: "Physical authentication is not complete"
          })
        );
      }
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
    }if (repeatedScanDetected) {
  console.warn("VERIFIED product has repeated scan history");
}

    return res.status(200).json(
      buildResponse("VERIFIED", {
        tagId: savedRecord.tag_id,
        product: savedRecord.product ?? product.product,
        brand: savedRecord.brand ?? product.brand,
        verificationId: savedRecord.verification_id,
        verifiedAt: savedRecord.created_at,
        physicalAuthentication
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
  physicalAuthEnabled,
  scanHistoryEnabled,
  sunValidationEnabled,
  validateSunMac,
  supabaseHeaders
};
