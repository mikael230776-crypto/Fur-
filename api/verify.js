const VERIFIED_TAGS = {
  "FUR-000001": {
    product: "Organic Cotton Tote Bag",
    brand: "Example Brand Ltd"
  },
  "FUR-000002": {
    product: "Recycled Cotton Shopper",
    brand: "Example Brand Ltd"
  },
  "FUR-000003": {
    product: "Organic Cotton Drawstring Bag",
    brand: "Sample Maker Ltd"
  }
};

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

export default function handler(req, res) {
  const { tagId } = req.query ?? {};

  if (!tagId) {
    return res.status(400).json(
      buildResponse("ERROR", {
        message: "Missing tagId"
      })
    );
  }

  const product = VERIFIED_TAGS[tagId];

  if (product) {
    return res.status(200).json(
      buildResponse("VERIFIED", {
        tagId,
        verificationId: createVerificationId(tagId),
        verifiedAt: new Date().toISOString(),
        ...product
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

export { VERIFIED_TAGS, buildResponse, createVerificationId };
