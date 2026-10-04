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

  /*
   * F.U.R DPP Step 3 implementation boundary
   *
   * Public identifier:
   *   GTIN + serial number
   *
   * Public DPP fields will be assembled from the authoritative
   * F.U.R Registry/DPP storage layer.
   *
   * Never expose:
   *   - NTAG UID
   *   - SUN/SDM counter
   *   - CMAC
   *   - secret keys
   *   - service-role credentials
   *   - raw database structure
   *   - verificationId
   *   - verifiedAt
   *
   * Existing /api/verify remains unchanged.
   */

  return sendError(
    res,
    404,
    "PASSPORT_NOT_FOUND",
    "No DPP passport exists for this identifier",
    requestId
  );
}
