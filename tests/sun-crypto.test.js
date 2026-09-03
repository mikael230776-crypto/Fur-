import test from "node:test";
import assert from "node:assert/strict";

import {
  aesCmac,
  hexToBuffer,
  secureEqual,
  truncateSdmMac
} from "../api/sun-crypto.js";

const key = hexToBuffer("2b7e151628aed2a6abf7158809cf4f3c");

test("AES-CMAC matches NIST empty-message vector", () => {
  const mac = aesCmac(key, Buffer.alloc(0));
  assert.equal(mac.toString("hex"), "bb1d6929e95937287fa37d129b756746");
});

test("AES-CMAC matches NIST one-block vector", () => {
  const message = hexToBuffer("6bc1bee22e409f96e93d7e117393172a");
  const mac = aesCmac(key, message);
  assert.equal(mac.toString("hex"), "070a16b46b4d4144f79bdd9dd04a287c");
});

test("AES-CMAC matches NIST multi-block vector", () => {
  const message = hexToBuffer(
    "6bc1bee22e409f96e93d7e117393172a" +
      "ae2d8a571e03ac9c9eb76fac45af8e51" +
      "30c81c46a35ce411"
  );
  const mac = aesCmac(key, message);
  assert.equal(mac.toString("hex"), "dfa66747de9ae63030ca32611497c827");
});

test("truncates an SDM MAC to its odd-indexed bytes", () => {
  const fullMac = hexToBuffer("000102030405060708090a0b0c0d0e0f");
  assert.equal(truncateSdmMac(fullMac).toString("hex"), "01030507090b0d0f");
});

test("hex parser rejects malformed and incorrectly sized values", () => {
  assert.throws(() => hexToBuffer("xyz"), /Invalid hexadecimal value/);
  assert.throws(() => hexToBuffer("0011", 16), /Expected 16 bytes/);
});

test("constant-time comparison handles equal and unequal values", () => {
  assert.equal(secureEqual(Buffer.from("same"), Buffer.from("same")), true);
  assert.equal(secureEqual(Buffer.from("same"), Buffer.from("diff")), false);
  assert.equal(secureEqual(Buffer.from("short"), Buffer.from("longer")), false);
});
