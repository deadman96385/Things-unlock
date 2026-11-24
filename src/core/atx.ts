const VERSION_BYTES = 4;
const FORMAT_VERSION = 1;
const SHA256_BYTES = 32;
const CHALLENGE_NONCE_BYTES = 16;
const RSA_BITS = 4096;
const RSA_BYTES = RSA_BITS / 8;
const AVB_RSA_HEADER_BYTES = 8;
const AVB_RSA_PUBLIC_KEY_BYTES = AVB_RSA_HEADER_BYTES + 2 * RSA_BYTES;

export const CHALLENGE_BYTES = VERSION_BYTES + SHA256_BYTES + CHALLENGE_NONCE_BYTES;

const CERT_SUBJECT_OFFSET = VERSION_BYTES + AVB_RSA_PUBLIC_KEY_BYTES;
const CERT_USAGE_OFFSET = CERT_SUBJECT_OFFSET + SHA256_BYTES;
const CERT_KEY_VERSION_OFFSET = CERT_USAGE_OFFSET + SHA256_BYTES;
const CERT_SIGNED_BYTES = CERT_KEY_VERSION_OFFSET + 8;

export const CERT_BYTES = CERT_SIGNED_BYTES + RSA_BYTES;
export const CREDENTIAL_BYTES = VERSION_BYTES + 2 * CERT_BYTES + RSA_BYTES;
export const RSA_ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" } as const;
export type SigningCrypto = Pick<SubtleCrypto, "digest" | "importKey" | "sign" | "verify">;

export interface UnlockChallenge {
  readonly version: number;
  readonly productIdHash: string;
}

export function parseChallenge(bytes: Uint8Array): UnlockChallenge {
  if (bytes.byteLength !== CHALLENGE_BYTES) {
    throw new Error(`Expected a ${CHALLENGE_BYTES}-byte ATX challenge.`);
  }

  const version = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, true);
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported ATX challenge version ${version}.`);
  }

  return { version, productIdHash: toHex(bytes.subarray(VERSION_BYTES, VERSION_BYTES + SHA256_BYTES)) };
}

export function copyChallengeNonce(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes.subarray(CHALLENGE_BYTES - CHALLENGE_NONCE_BYTES));
}

export async function parseCertificate(subtle: SigningCrypto, input: Uint8Array, role: "PIK" | "PUK") {
  if (input.byteLength !== CERT_BYTES) {
    throw new Error(`Expected a ${CERT_BYTES}-byte ATX ${role} certificate.`);
  }

  const bytes = new Uint8Array(input);
  const view = new DataView(bytes.buffer);
  if (view.getUint32(0, true) !== FORMAT_VERSION) {
    throw new Error(`Unsupported ATX ${role} certificate version.`);
  }
  if (view.getUint32(VERSION_BYTES) !== RSA_BITS) {
    throw new Error(`Expected an RSA-4096 public key in the ${role} certificate.`);
  }

  const usage = role === "PIK" ? "com.google.android.things.vboot.ca" : "com.google.android.things.vboot.unlock";
  const expectedUsage = await subtle.digest("SHA-256", new TextEncoder().encode(usage));
  if (toHex(bytes.subarray(CERT_USAGE_OFFSET, CERT_KEY_VERSION_OFFSET)) !== toHex(new Uint8Array(expectedUsage))) {
    throw new Error(`The ${role} certificate has the wrong ATX key usage.`);
  }

  const modulusOffset = VERSION_BYTES + AVB_RSA_HEADER_BYTES;
  const modulus = bytes.subarray(modulusOffset, modulusOffset + RSA_BYTES);
  if (modulus[0] < 0x80 || modulus[RSA_BYTES - 1] % 2 === 0) {
    throw new Error(`Invalid RSA-4096 modulus in the ${role} certificate.`);
  }

  // AVB encodes the modulus and Montgomery parameters and uses a fixed exponent of 65537.
  const publicKey = await subtle.importKey("jwk", {
    kty: "RSA",
    n: btoa(String.fromCharCode(...modulus)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    e: "AQAB",
  }, RSA_ALGORITHM, false, ["verify"]);

  return {
    bytes,
    publicKey,
    productIdHash: toHex(bytes.subarray(CERT_SUBJECT_OFFSET, CERT_USAGE_OFFSET)),
    keyVersion: view.getBigUint64(CERT_KEY_VERSION_OFFSET, true),
    signedData: bytes.subarray(0, CERT_SIGNED_BYTES),
    signature: bytes.subarray(CERT_SIGNED_BYTES),
  };
}

export function encodeCredential(pik: Uint8Array, puk: Uint8Array, signature: ArrayBuffer): Uint8Array<ArrayBuffer> {
  if (signature.byteLength !== RSA_BYTES) {
    throw new Error(`Expected a ${RSA_BYTES}-byte ATX challenge signature.`);
  }

  const bytes = new Uint8Array(CREDENTIAL_BYTES);
  new DataView(bytes.buffer).setUint32(0, FORMAT_VERSION, true);
  bytes.set(pik, VERSION_BYTES);
  bytes.set(puk, VERSION_BYTES + CERT_BYTES);
  bytes.set(new Uint8Array(signature), VERSION_BYTES + 2 * CERT_BYTES);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
