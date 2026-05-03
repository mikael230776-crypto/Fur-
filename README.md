# FUR Verification

## Verification API contract

Endpoint: `GET /api/verify?tagId=<TAG_ID>`

### Responses

- **200 OK**
  ```json
  {
    "status": "VERIFIED",
    "tagId": "FUR-000001",
    "product": "Organic Cotton Tote Bag",
    "brand": "Example Brand Ltd"
  }
  ```

- **404 Not Found**
  ```json
  {
    "status": "NOT_VERIFIED",
    "tagId": "FUR-999999",
    "message": "Product not found"
  }
  ```

- **400 Bad Request**
  ```json
  {
    "status": "ERROR",
    "message": "Missing tagId"
  }
  ```

## Local test command

```bash
npm test
```
