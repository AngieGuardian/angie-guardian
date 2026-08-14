// Angie Guardian Argon2id worker. The cryptographic implementation is the
// pinned PHC reference build loaded below; this file only marshals bytes.
"use strict";

importScripts("/__guardian/assets/argon2id-runtime-1b3aa08f6d118ad6.js");

let modulePromise;

function fromHex(value) {
  if (typeof value !== "string" || value.length % 2 !== 0) throw new Error("invalid hex");
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) throw new Error("invalid hex");
    out[i] = byte;
  }
  return out;
}

function toHex(value) {
  let out = "";
  for (const byte of value) out += byte.toString(16).padStart(2, "0");
  return out;
}

self.onmessage = async (event) => {
  const { challenge, salt, memory_kib, iterations, wasm_url } = event.data;
  try {
    if (memory_kib < 8192 || memory_kib > 32768 || iterations < 1 || iterations > 3) {
      throw new Error("Argon2id parameters outside Guardian bounds");
    }
    modulePromise ||= GuardianArgon2Module({ locateFile: () => wasm_url });
    const mod = await modulePromise;
    const input = new TextEncoder().encode(challenge);
    const saltBytes = fromHex(salt);
    if (saltBytes.length !== 16) throw new Error("invalid Argon2id salt");

    const inputPtr = mod._malloc(input.length);
    const saltPtr = mod._malloc(saltBytes.length);
    const outputPtr = mod._malloc(32);
    if (!inputPtr || !saltPtr || !outputPtr) throw new Error("Argon2id memory allocation failed");
    try {
      mod.HEAPU8.set(input, inputPtr);
      mod.HEAPU8.set(saltBytes, saltPtr);
      const rc = mod._argon2_hash(
        iterations, memory_kib, 1,
        inputPtr, input.length, saltPtr, saltBytes.length,
        outputPtr, 32, 0, 0,
        2, 0x13,
      );
      if (rc !== 0) throw new Error("Argon2id failed with code " + rc);
      const proof = toHex(mod.HEAPU8.slice(outputPtr, outputPtr + 32));
      self.postMessage({ proof });
    } finally {
      mod._free(inputPtr);
      mod._free(saltPtr);
      mod._free(outputPtr);
    }
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : "Argon2id failed" });
  }
};

