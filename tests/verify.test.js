import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/verify.js';

function createRes() {
  return {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.payload = body;
      return this;
    }
  };
}

test('returns 400 ERROR when tagId is missing', () => {
  const req = { query: {} };
  const res = createRes();

  handler(req, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.payload.status, 'ERROR');
  assert.equal(res.payload.message, 'Missing tagId');
});


test('returns 400 ERROR when query object is missing', () => {
  const req = {};
  const res = createRes();

  handler(req, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.payload.status, 'ERROR');
  assert.equal(res.payload.message, 'Missing tagId');
});

test('returns 200 VERIFIED payload for known tag', () => {
  const req = { query: { tagId: 'FUR-000001' } };
  const res = createRes();

  handler(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.status, 'VERIFIED');
  assert.equal(res.payload.tagId, 'FUR-000001');
  assert.equal(res.payload.product, 'Organic Cotton Tote Bag');
  assert.equal(res.payload.brand, 'Example Brand Ltd');
});

test('returns 404 NOT_VERIFIED for unknown tag', () => {
  const req = { query: { tagId: 'FUR-999999' } };
  const res = createRes();

  handler(req, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.payload.status, 'NOT_VERIFIED');
  assert.equal(res.payload.tagId, 'FUR-999999');
  assert.equal(res.payload.message, 'Product not found');
});
