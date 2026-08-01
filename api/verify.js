function buildResponse(status, extras = {}) {
  return {
    status,
    ...extras
  };
}

function createVerificationId(tagId) {
  const now = new Date();
  const date = now.toISOString().slice(0, 10).replaceAll("-", "");
  const time = now.toISOString().slice(11, 19).replaceAll(":", "");
  const tagSuffix = tagId.replace(/[^0-9]/g, "").slice(-6).padStart(6, "0");
  return `VR-${date}-${time}-${tagSuffix}`;
}

export default async function handler(req, res) {
  const rawTagId = req.query?.tagId;
  const tagId =
    typeof rawTagId === "string" ? rawTagId.trim().toUpperCase() : rawTagId;

  if (!tagId) {
    return res.status(400).json(
      buildResponse("ERROR", {
        message: "Missing tagId"
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
    const endpoint =
      `${supabaseUrl}/rest/v1/Products` +
      `?tag_id=eq.${encodeURIComponent(tagId)}` +
      `&select=tag_id,product,brand,status` +
      `&limit=1`;

    const response = await fetch(endpoint, {
      headers: {
        apikey: supabaseSecretKey,
        Authorization: `Bearer ${supabaseSecretKey}`,
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Supabase query failed:", response.status, errorText);
      return res.status(502).json(
        buildResponse("ERROR", {
          message: "Registry lookup failed"
        })
      );
    }

    const rows = await response.json();
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

    return res.status(200).json(
      buildResponse("VERIFIED", {
        tagId: product.tag_id,
        product: product.product,
        brand: product.brand,
        verificationId: createVerificationId(product.tag_id),
        verifiedAt: new Date().toISOString()
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

export { buildResponse, createVerificationId };
