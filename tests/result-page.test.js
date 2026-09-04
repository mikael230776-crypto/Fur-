import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

test("result page forwards SUN authentication parameters", async () => {
  const html = await readFile(new URL("../result.html", import.meta.url), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "result.html script was not found");

  const elements = new Map();
  const requestedUrls = [];
  const document = {
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          className: "",
          hidden: false,
          textContent: ""
        });
      }
      return elements.get(id);
    }
  };

  const context = {
    URLSearchParams,
    Intl,
    Date,
    console,
    document,
    window: {
      location: {
        search:
          "?tagId=FUR-000001&uid=04917DA291D90&ctr=000001&cmac=0011223344556677"
      }
    },
    async fetch(url) {
      requestedUrls.push(url);
      return {
        ok: false,
        status: 403,
        async json() {
          return { status: "NOT_VERIFIED", message: "Test response" };
        }
      };
    }
  };

  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(requestedUrls, [
    "/api/verify?tagId=FUR-000001&uid=04917DA291D90&ctr=000001&cmac=0011223344556677"
  ]);
});
