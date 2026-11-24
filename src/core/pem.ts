import { RSA_ALGORITHM } from "./atx.js";
import type { SigningCrypto } from "./atx.js";

export const MAX_PRIVATE_KEY_PEM_BYTES = 16 * 1024;

export async function importUnlockKey(subtle: SigningCrypto, pem: Uint8Array): Promise<CryptoKey> {
  if (pem.byteLength > MAX_PRIVATE_KEY_PEM_BYTES) {
    throw new Error(`Private key PEM exceeds ${MAX_PRIVATE_KEY_PEM_BYTES} bytes.`);
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(pem).trim();
  } catch {
    throw new Error("Expected a UTF-8 private key PEM.");
  }

  const match = /^-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY)-----\r?\n([A-Za-z0-9+/=\r\n \t]+)\r?\n-----END \1-----$/.exec(text);
  if (!match) {
    throw new Error("Expected an unencrypted PKCS#8 or RSA PKCS#1 private key PEM.");
  }

  let der: Uint8Array<ArrayBuffer> | undefined;
  let pkcs8: Uint8Array<ArrayBuffer> | undefined;
  let key: CryptoKey;
  try {
    der = Uint8Array.from(atob(match[2].replace(/\s/g, "")), (character) => character.charCodeAt(0));
    pkcs8 = match[1] === "RSA PRIVATE KEY" ? wrapRsaPrivateKey(der) : der;
    key = await subtle.importKey("pkcs8", pkcs8, RSA_ALGORITHM, false, ["sign"]);
  } catch {
    throw new Error("Invalid RSA private key PEM.");
  } finally {
    pkcs8?.fill(0);
    if (der !== pkcs8) der?.fill(0);
  }

  const { modulusLength } = key.algorithm as RsaHashedKeyAlgorithm;
  if (modulusLength !== 4096) {
    throw new Error("The unlock private key must be RSA-4096.");
  }
  return key;
}

function wrapRsaPrivateKey(pkcs1: Uint8Array): Uint8Array<ArrayBuffer> {
  // PKCS#8 PrivateKeyInfo v0 with the rsaEncryption OID and NULL parameters.
  const versionAndAlgorithm = Uint8Array.of(
    0x02, 0x01, 0x00,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  );
  const octetHeader = derHeader(0x04, pkcs1.byteLength);
  const sequenceHeader = derHeader(0x30, versionAndAlgorithm.length + octetHeader.length + pkcs1.byteLength);
  const result = new Uint8Array(sequenceHeader.length + versionAndAlgorithm.length + octetHeader.length + pkcs1.byteLength);
  result.set(sequenceHeader);
  result.set(versionAndAlgorithm, sequenceHeader.length);
  result.set(octetHeader, sequenceHeader.length + versionAndAlgorithm.length);
  result.set(pkcs1, result.length - pkcs1.byteLength);
  return result;
}

function derHeader(tag: number, length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(tag, length);
  if (length <= 0xff) return Uint8Array.of(tag, 0x81, length);
  return Uint8Array.of(tag, 0x82, length >>> 8, length & 0xff);
}
