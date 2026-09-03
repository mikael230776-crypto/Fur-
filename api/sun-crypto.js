import { createCipheriv, timingSafeEqual } from "node:crypto";

const BLOCK_SIZE = 16;
const RB = 0x87;

function xorBlocks(left, right) {
  const output = Buffer.alloc(BLOCK_SIZE);

  for (let index = 0; index < BLOCK_SIZE; index += 1) {
    output[index] = left[index] ^ right[index];
  }

  return output;
}

function leftShiftBlock(block) {
  const output = Buffer.alloc(BLOCK_SIZE);
  let carry = 0;

  for (let index = BLOCK_SIZE - 1; index >= 0; index -= 1) {
    const value = block[index];
    output[index] = ((value << 1) & 0xff) | carry;
    carry = (value & 0x80) === 0x80 ? 1 : 0;
  }

  return { output, carry };
}

function aesEncryptBlock(key, block) {
  const cipher = createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);

  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function createSubkey(block) {
  const shifted = leftShiftBlock(block);

  if (shifted.carry === 1) {
    shifted.output[BLOCK_SIZE - 1] ^= RB;
  }

  return shifted.output;
}

export function hexToBuffer(value, expectedBytes) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]+$/i.test(value) ||
    value.length % 2 !== 0
  ) {
    throw new Error("Invalid hexadecimal value");
  }

  const result = Buffer.from(value, "hex");

  if (expectedBytes && result.length !== expectedBytes) {
    throw new Error(`Expected ${expectedBytes} bytes`);
  }

  return result;
}

export function aesCmac(keyInput, messageInput) {
  const key = Buffer.from(keyInput);
  const message = Buffer.from(messageInput);

  if (key.length !== BLOCK_SIZE) {
    throw new Error("AES-CMAC requires a 16-byte key");
  }

  const zeroBlock = Buffer.alloc(BLOCK_SIZE);
  const firstSubkey = createSubkey(aesEncryptBlock(key, zeroBlock));
  const secondSubkey = createSubkey(firstSubkey);

  const complete =
    message.length > 0 && message.length % BLOCK_SIZE === 0;
  const blockCount = Math.max(1, Math.ceil(message.length / BLOCK_SIZE));
  const lastOffset = (blockCount - 1) * BLOCK_SIZE;

  let lastBlock;

  if (complete) {
    lastBlock = xorBlocks(
      message.subarray(lastOffset, lastOffset + BLOCK_SIZE),
      firstSubkey
    );
  } else {
    const padded = Buffer.alloc(BLOCK_SIZE);
    const remainder = message.subarray(lastOffset);

    remainder.copy(padded);
    padded[remainder.length] = 0x80;
    lastBlock = xorBlocks(padded, secondSubkey);
  }

  let state = zeroBlock;

  for (let index = 0; index < blockCount - 1; index += 1) {
    const block = message.subarray(
      index * BLOCK_SIZE,
      (index + 1) * BLOCK_SIZE
    );
    state = aesEncryptBlock(key, xorBlocks(state, block));
  }

  return aesEncryptBlock(key, xorBlocks(state, lastBlock));
}

export function truncateSdmMac(fullMacInput) {
  const fullMac = Buffer.from(fullMacInput);

  if (fullMac.length !== BLOCK_SIZE) {
    throw new Error("Full SDM MAC must contain 16 bytes");
  }

  return Buffer.from([
    fullMac[1],
    fullMac[3],
    fullMac[5],
    fullMac[7],
    fullMac[9],
    fullMac[11],
    fullMac[13],
    fullMac[15],
  ]);
}

export function secureEqual(leftInput, rightInput) {
  const left = Buffer.from(leftInput);
  const right = Buffer.from(rightInput);

  return left.length === right.length && timingSafeEqual(left, right);
}

