import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/verify.js';

const originalFetch = globalThis.fetch;
const originalSupabaseUrl = process.env.SUPABASE_URL;
const originalSupabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

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

function configureSupabase() {
  process.env.SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-secret-key';
}

afterEach(() => {
  globalThis.fetch = originalFetch;

  if (originalSupabaseUrl === undefined) {
    delete process.env.SUPABASE_URL;
  } else {
    process.env.SUPABASE_URL = originalSupabaseUrl;
  }

  if (originalSupabaseSecretKey === undefined) {
    delete process.env.SUPABASE_SECRET_KEY;
  } else {
    process.env.SUPABASE_SECRET_KEY = originalSupabaseSecretKey;
  }
});

test('returns 400 ERROR when tagId is missing', async () => {
  const res = createRes();

  await handler({ query: {} }, res);

  assert.equal(res.statusCode, 400);
  assert.deepEqual(res.payload, {
    status: 'ERROR',
    message: 'Missing tagId'
  });
});

test('returns 400 ERROR when query object is missing', async () => {
  const res = createRes();

  await handler({}, res);

  assert.equal(res.statusCode, 400);
  assert.deepEqual(res.payload, {
    status: 'ERROR',
    message: 'Missing tagId'
  });
});

test('returns 500 ERROR when Supabase configuration is missing', async () => {
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;
  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.equal(res.statusCode, 500);
  assert.equal(res.payload.status, 'ERROR');
  assert.equal(res.payload.message, 'Supabase environment variables are missing');
});

test('returns VERIFIED registry data for a known tag', async () => {
  configureSupabase();
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => [{
      tag_id: 'FUR-000001',
      product: 'Organic Cotton Tote Bag',
      brand: 'Example Brand Ltd',
      status: 'VERIFIED'
    }]
  });
  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.status, 'VERIFIED');
  assert.equal(res.payload.tagId, 'FUR-000001');
  assert.equal(res.payload.product, 'Organic Cotton Tote Bag');
  assert.equal(res.payload.brand, 'Example Brand Ltd');
  assert.match(res.payload.verificationId, /^VR-\d{8}-\d{6}-000001$/);
  assert.doesNotThrow(() => new Date(res.payload.verifiedAt));
});

test('normalises a lowercase tagId before querying the registry', async () => {
  configureSupabase();
  let requestedEndpoint;

  globalThis.fetch = async (endpoint) => {
    requestedEndpoint = endpoint;
    return {
      ok: true,
      json: async () => [{
        tag_id: 'FUR-000001',
        product: 'Organic Cotton Tote Bag',
        brand: 'Example Brand Ltd',
        status: 'VERIFIED'
      }]
    };
  };
  const res = createRes();

  await handler({ query: { tagId: '  fur-000001  ' } }, res);

  assert.match(requestedEndpoint, /tag_id=eq\.FUR-000001/);
  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.status, 'VERIFIED');
  assert.equal(res.payload.tagId, 'FUR-000001');
});

test('returns 404 NOT_VERIFIED when the registry has no matching tag', async () => {
  configureSupabase();
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => []
  });
  const res = createRes();

  await handler({ query: { tagId: 'FUR-999999' } }, res);

  assert.equal(res.statusCode, 404);
  assert.deepEqual(res.payload, {
    status: 'NOT_VERIFIED',
    tagId: 'FUR-999999',
    message: 'Product not found'
  });
});

test('returns 502 ERROR when the registry request fails', async () => {
  configureSupabase();
  globalThis.fetch = async () => ({
    ok: false,
    status: 500,
    text: async () => 'upstream failure'
  });
  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.equal(res.statusCode, 502);
  assert.deepEqual(res.payload, {
    status: 'ERROR',
    message: 'Registry lookup failed'
  });
});

test('returns 500 ERROR when the registry connection throws', async () => {
  configureSupabase();
  globalThis.fetch = async () => {
    throw new Error('network failure');
  };
  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.payload, {
    status: 'ERROR',
    message: 'Verification service is temporarily unavailable'
  });
});
