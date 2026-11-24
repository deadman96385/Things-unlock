import { copyChallengeNonce, encodeCredential, parseCertificate, parseChallenge, RSA_ALGORITHM } from "./atx.js";
import type { SigningCrypto, UnlockChallenge } from "./atx.js";
import { importUnlockKey } from "./pem.js";

export interface CredentialFiles {
  readonly pikCert: Uint8Array;
  readonly pukCert: Uint8Array;
  readonly pukKeyPem: Uint8Array;
}

export interface UnlockBundle {
  readonly name: string;
  readonly productIdHash: string;
  readonly keyVersion: bigint;
}

interface SigningMaterial {
  pikCert: Uint8Array;
  pukCert: Uint8Array;
  pukKey: CryptoKey;
  pukPublicKey: CryptoKey;
}

export function findMatches(challenge: UnlockChallenge, bundles: readonly UnlockBundle[]): UnlockBundle[] {
  return bundles.filter((bundle) => bundle.productIdHash === challenge.productIdHash);
}

export function createSigner(subtle: SigningCrypto) {
  const materials = new WeakMap<UnlockBundle, SigningMaterial>();

  async function importBundle(files: CredentialFiles, name: string): Promise<UnlockBundle> {
    const pik = await parseCertificate(subtle, files.pikCert, "PIK");
    const puk = await parseCertificate(subtle, files.pukCert, "PUK");
    if (!await subtle.verify(RSA_ALGORITHM.name, pik.publicKey, puk.signature, puk.signedData)) {
      throw new Error("The PIK certificate does not verify the PUK certificate signature.");
    }

    const pukKey = await importUnlockKey(subtle, files.pukKeyPem);
    const bundle = Object.freeze({ name, productIdHash: puk.productIdHash, keyVersion: puk.keyVersion });
    materials.set(bundle, { pikCert: pik.bytes, pukCert: puk.bytes, pukKey, pukPublicKey: puk.publicKey });
    return bundle;
  }

  async function createCredential(challengeBytes: Uint8Array, bundle: UnlockBundle): Promise<Uint8Array<ArrayBuffer>> {
    const challenge = parseChallenge(challengeBytes);
    const material = materials.get(bundle);
    if (!material) {
      throw new Error("Import the unlock bundle with this signer before generating a credential.");
    }
    if (challenge.productIdHash !== bundle.productIdHash) {
      throw new Error("The unlock bundle does not match the challenge product ID hash.");
    }

    // Web Crypto hashes the raw nonce with SHA-512 as part of RSASSA-PKCS1-v1_5.
    const nonce = copyChallengeNonce(challengeBytes);
    const signature = await subtle.sign(RSA_ALGORITHM.name, material.pukKey, nonce);
    if (!await subtle.verify(RSA_ALGORITHM.name, material.pukPublicKey, signature, nonce)) {
      throw new Error("The private key does not match the PUK certificate.");
    }

    return encodeCredential(material.pikCert, material.pukCert, signature);
  }

  return { importBundle, createCredential };
}
