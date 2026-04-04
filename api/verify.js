export default function handler(req, res) {
  const { tagId } = req.query;

  if (!tagId) {
    return res.status(400).json({
      status: "ERROR",
      message: "Missing Tag ID"
    });
  }

  if (tagId === "FUR-000001") {
    return res.status(200).json({
      status: "VERIFIED",
      product: "Organic Cotton Tote Bag",
      brand: "Example Brand Ltd"
    });
  }

  return res.status(404).json({
    status: "NOT VERIFIED",
    message: "Product not found"
  });
}

  
  

