import test from "node:test";
import assert from "node:assert/strict";
import {
  getPhysicalAuthSummary,
  physicalAuthEnabled,
  publicPhysicalAuthSummary
} from "../api/physical-auth.js";

function response(json, ok = true) {
  return { ok, json: async () => json };
}

test("physical authentication is disabled by default", () => {
  delete process.env.ENABLE_PHYSICAL_AUTH;
  assert.equal(physicalAuthEnabled(), false);
});

test("reports no requirement when a tag has no profile", () => {
  assert.deepEqual(publicPhysicalAuthSummary(null, null), {
    required: false,
    status: "NOT_REQUIRED"
  });
});

test("requires inspection for an active profile without evidence", () => {
  assert.deepEqual(
    publicPhysicalAuthSummary({ method: "UV_MARK" }, null),
    {
      required: true,
      method: "UV_MARK",
      status: "NOT_INSPECTED",
      inspectedAt: null
    }
  );
});

test("maps present evidence to a passed public result", () => {
  assert.deepEqual(
    publicPhysicalAuthSummary(
      { method: "TAMPER_EVIDENT" },
      { result: "PRESENT", inspected_at: "2026-09-05T10:00:00Z" }
    ),
    {
      required: true,
      method: "TAMPER_EVIDENT",
      status: "PASSED",
      inspectedAt: "2026-09-05T10:00:00Z"
    }
  );
});

test("maps absent or damaged evidence to failure", () => {
  for (const result of ["ABSENT", "DAMAGED"]) {
    assert.equal(
      publicPhysicalAuthSummary(
        { method: "MACHINE_TAGGANT" },
        { result, inspected_at: "2026-09-05T10:00:00Z" }
      ).status,
      "FAILED"
    );
  }
});

test("does not expose evidence hashes or internal references", () => {
  const summary = publicPhysicalAuthSummary(
    { method: "FORENSIC_MARKER", supplier_reference: "private" },
    {
      result: "INCONCLUSIVE",
      inspected_at: "2026-09-05T10:00:00Z",
      evidence_sha256: "a".repeat(64),
      evidence_reference: "private/photo"
    }
  );

  assert.equal(summary.status, "REVIEW_REQUIRED");
  assert.equal("evidence_sha256" in summary, false);
  assert.equal("evidence_reference" in summary, false);
  assert.equal("supplier_reference" in summary, false);
});

test("loads the latest inspection for an active profile", async () => {
  const originalFetch = global.fetch;
  const requestedUrls = [];
  global.fetch = async (url) => {
    requestedUrls.push(url);
    if (url.includes("physical_auth_profiles")) {
      return response([{ profile_id: "profile-1", method: "UV_MARK" }]);
    }
    return response([
      { result: "PRESENT", inspected_at: "2026-09-05T10:00:00Z" }
    ]);
  };

  try {
    const result = await getPhysicalAuthSummary(
      "https://example.supabase.co",
      "secret",
      "FUR-000001",
      { Authorization: "Bearer secret" }
    );

    assert.equal(result.ok, true);
    assert.equal(result.summary.status, "PASSED");
    assert.match(requestedUrls[0], /status=eq\.ACTIVE/);
    assert.match(requestedUrls[1], /order=inspected_at\.desc/);
    assert.match(requestedUrls[1], /limit=1/);
  } finally {
    global.fetch = originalFetch;
  }
});

test("does not query inspections when no profile is assigned", async () => {
  const originalFetch = global.fetch;
  let fetchCount = 0;
  global.fetch = async () => {
    fetchCount += 1;
    return response([]);
  };

  try {
    const result = await getPhysicalAuthSummary(
      "https://example.supabase.co",
      "secret",
      "FUR-000001",
      {}
    );
    assert.equal(result.ok, true);
    assert.equal(result.summary.status, "NOT_REQUIRED");
    assert.equal(fetchCount, 1);
  } finally {
    global.fetch = originalFetch;
  }
});

test("fails closed when physical evidence storage is unavailable", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => response([], false);

  try {
    const result = await getPhysicalAuthSummary(
      "https://example.supabase.co",
      "secret",
      "FUR-000001",
      {}
    );
    assert.deepEqual(result, {
      ok: false,
      message: "Physical authentication profile lookup failed"
    });
  } finally {
    global.fetch = originalFetch;
  }
});
