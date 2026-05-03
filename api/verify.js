const VERIFIED_TAGS = {
  "FUR-000001": {
    product: "Organic Cotton Tote Bag",
    brand: "Example Brand Ltd"
  }
};

function buildResponse(status, extras = {}) {
  return {
    status,
    ...extras
  };
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

export { VERIFIED_TAGS, buildResponse };
