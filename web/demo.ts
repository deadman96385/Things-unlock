import {
  AVB_RSA_HEADER_BYTES, CERT_BYTES, CERTIFICATE_USAGE, CERT_KEY_VERSION_OFFSET, CERT_SIGNED_BYTES,
  CERT_SUBJECT_OFFSET, CERT_USAGE_OFFSET, CHALLENGE_BYTES, FORMAT_VERSION, RSA_ALGORITHM,
  RSA_BITS, RSA_BYTES, VERSION_BYTES,
} from "../src/core/atx.js";
import type { CredentialFiles } from "../src/index.js";

export async function createDemo(crypto: Crypto): Promise<{ challenge: Uint8Array<ArrayBuffer>; files: CredentialFiles }> {
  const { subtle } = crypto;
  const algorithm = { ...RSA_ALGORITHM, modulusLength: RSA_BITS, publicExponent: Uint8Array.of(1, 0, 1) };
  const [pik, puk] = await Promise.all([
    subtle.generateKey(algorithm, false, ["sign", "verify"]),
    subtle.generateKey(algorithm, true, ["sign", "verify"]),
  ]);
  const subject = new Uint8Array(await subtle.digest("SHA-256", crypto.getRandomValues(new Uint8Array(16))));
  const challenge = crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES));
  new DataView(challenge.buffer).setUint32(0, FORMAT_VERSION, true);
  challenge.set(subject, VERSION_BYTES);

  // The demo uses an ephemeral, self-signed PIK outside any device trust chain.
  const [pikCert, pukCert] = await Promise.all([
    demoCertificate(subtle, pik.publicKey, pik.privateKey, subject, "PIK"),
    demoCertificate(subtle, puk.publicKey, pik.privateKey, subject, "PUK"),
  ]);
  const der = new Uint8Array(await subtle.exportKey("pkcs8", puk.privateKey));
  try {
    const base64 = btoa(String.fromCharCode(...der));
    const pem = "-----BEGIN PRIVATE KEY-----\n" + base64.match(/.{1,64}/g)!.join("\n") + "\n-----END PRIVATE KEY-----\n";
    return { challenge, files: { pikCert, pukCert, pukKeyPem: new TextEncoder().encode(pem) } };
  } finally {
    der.fill(0);
  }
}

async function demoCertificate(
  subtle: SubtleCrypto,
  publicKey: CryptoKey,
  signingKey: CryptoKey,
  subject: Uint8Array<ArrayBuffer>,
  role: keyof typeof CERTIFICATE_USAGE,
): Promise<Uint8Array<ArrayBuffer>> {
  const jwk = await subtle.exportKey("jwk", publicKey);
  if (!jwk.n) throw new Error("The browser did not generate an RSA demo key.");
  const modulus = Uint8Array.from(atob(jwk.n.replace(/-/g, "+").replace(/_/g, "/")), (character) => character.charCodeAt(0));
  const n = modulus.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
  const usage = await subtle.digest("SHA-256", new TextEncoder().encode(CERTIFICATE_USAGE[role]));

  const cert = new Uint8Array(CERT_BYTES);
  const view = new DataView(cert.buffer);
  view.setUint32(0, FORMAT_VERSION, true);
  view.setUint32(VERSION_BYTES, RSA_BITS);
  // AVB stores the negative modular inverse of n modulo 2^32 and R squared modulo n.
  let inverse = 1n;
  for (let bits = 1; bits < 32; bits *= 2) inverse = BigInt.asUintN(32, inverse * (2n - n * inverse));
  view.setUint32(VERSION_BYTES + 4, Number(BigInt.asUintN(32, -inverse)));
  const modulusOffset = VERSION_BYTES + AVB_RSA_HEADER_BYTES;
  cert.set(modulus, modulusOffset);
  let rr = (1n << BigInt(2 * RSA_BITS)) % n;
  for (let offset = CERT_SUBJECT_OFFSET - 1; offset >= modulusOffset + RSA_BYTES; offset--) {
    cert[offset] = Number(rr & 0xffn);
    rr >>= 8n;
  }

  cert.set(subject, CERT_SUBJECT_OFFSET);
  cert.set(new Uint8Array(usage), CERT_USAGE_OFFSET);
  view.setBigUint64(CERT_KEY_VERSION_OFFSET, 1n, true);
  const signature = await subtle.sign(RSA_ALGORITHM.name, signingKey, cert.subarray(0, CERT_SIGNED_BYTES));
  cert.set(new Uint8Array(signature), CERT_SIGNED_BYTES);
  return cert;
}
