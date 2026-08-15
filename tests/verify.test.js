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
}); test('returns VERIFIED registry data for a known tag', async () => {
  configureSupabase();

  globalThis.fetch = async (endpoint, options = {}) => {
  if (endpoint.includes('/rest/v1/Products')) {
    return {
      ok: true,
      json: async () => [{
        tag_id: 'FUR-000001',
        product: 'Organic Cotton Tote Bag',
        brand: 'Example Brand Ltd',
        status: 'VERIFIED'
      }]
    };
  }

  if (options.method === 'POST') {
    const record = JSON.parse(options.body);

    return {
      ok: true,
      json: async () => [{
        ...record,
        created_at: '2026-08-14T10:00:00.000Z'
      }]
    };
  }

  return {
    ok: true,
    json: async () => []
  };
};
  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.status, 'VERIFIED');
  assert.equal(res.payload.tagId, 'FUR-000001');
  assert.equal(res.payload.product, 'Organic Cotton Tote Bag');
  assert.equal(res.payload.brand, 'Example Brand Ltd');
  assert.match(
  res.payload.verificationId,
  /^VR-\d{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
);
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
test('checks recent scan history for repeated use of the same tag', async () => {
  configureSupabase();
  process.env.ENABLE_SCAN_HISTORY = 'true';

  let historyChecked = false;

  globalThis.fetch = async (endpoint, options = {}) => {
    if (
      endpoint.includes('/rest/v1/verification_scans') &&
      (!options.method || options.method === 'GET')
    ) {
      historyChecked = true;

      return {
        ok: true,
        json: async () => [
          { tag_id: 'FUR-000001' },
          { tag_id: 'FUR-000001' },
          { tag_id: 'FUR-000001' },
          { tag_id: 'FUR-000001' },
          { tag_id: 'FUR-000001' }
        ]
      };
    }

    if (endpoint.includes('/rest/v1/Products')) {
      return {
        ok: true,
        json: async () => [{
          tag_id: 'FUR-000001',
          product: 'Organic Cotton Tote Bag',
          brand: 'Example Brand Ltd',
          status: 'VERIFIED'
        }]
      };
    }

    if (endpoint.includes('/rest/v1/verification_records')) {
      return {
        ok: true,
        json: async () => [{
          verification_id: 'VR-20260815-00000000-0000-0000-0000-000000000001',
          tag_id: 'FUR-000001',
          created_at: '2026-08-15T07:30:00.000Z',
          status: 'VERIFIED',
          product: 'Organic Cotton Tote Bag',
          brand: 'Example Brand Ltd'
        }]
      };
    }

    if (
      endpoint.includes('/rest/v1/verification_scans') &&
      options.method === 'POST'
    ) {
      return {
        ok: true,
        json: async () => []
      };
    }

    return {
      ok: true,
      json: async () => []
    };
  };

  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.equal(historyChecked, true);
});
test('suspended NFC tag is refused verification', async () => {
  process.env.SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-secret';

  globalThis.fetch = async (endpoint) => {
    if (endpoint.includes('/rest/v1/products')) {
      return {
        ok: true,
        json: async () => [{
          tag_id: 'FUR-000001',
          product: 'Organic Cotton Tote Bag',
          brand: 'Example Brand Ltd',
          status: 'SUSPENDED'
        }]
      };
    }

    return {
      ok: true,
      json: async () => []
    };
  };

  const res = createRes();

  await handler({ query: { tagId: 'FUR-000001' } }, res);

  assert.notEqual(res.statusCode, 200);
});
