export default function handler(req, res) {
  const { tagId } = req.query;

  if (!tagId) {
    return res.status(400).json({
      status: "ERROR",
      message: "Missing Tag ID"
    });
  }

  const registry = {
    "FUR-2026-000001": {
      product: "Organic Cotton Tote Bag",
      brand: "Example Brand Ltd",
      status: "VERIFIED"
    }
  };

  if (registry[tagId]) {
    return res.status(200).json(registry[tagId]);
  }

  return res.status(404).json({
    status: "NOT VERIFIED",
    message: "Product not found"
  });
}
export default function handler(req, res) {
  const { tagId } = req.query;

  if (!tagId) {
    return res.status(400).json({
      status: "ERROR",
      message: "Missing Tag ID"
    });
  }

  const registry = {
    "FUR-2026-000001": {
      product: "Organic Cotton Tote Bag",
      brand: "Example Brand Ltd",
      status: "VERIFIED"
    }
  };

  if (registry[tagId]) {
    return res.status(200).json(registry[tagId]);
  }

  return res.status(404).json({
    status: "NOT VERIFIED",
    message: "Product not found"
  });
}
