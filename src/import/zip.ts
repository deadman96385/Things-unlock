import { Uint8ArrayReader, ZipReader } from "@zip.js/zip.js/lib/zip-native.js";
import type { FileEntry } from "@zip.js/zip.js/lib/zip-native.js";
import { CERT_BYTES } from "../core/atx.js";
import { MAX_PRIVATE_KEY_PEM_BYTES } from "../core/pem.js";
import type { CredentialFiles } from "../core/signer.js";

export const MAX_CREDENTIAL_ZIP_BYTES = 1024 * 1024;
const MAX_ZIP_ENTRIES = 128;

const CREDENTIAL_ENTRIES = [
  { role: "pikCert", filename: /^pik_certificate.*\.bin$/, label: "PIK certificate" },
  { role: "pukCert", filename: /^puk_certificate.*\.bin$/, label: "PUK certificate" },
  { role: "pukKeyPem", filename: /^puk.*\.pem$/, label: "PUK private key" },
] as const;

export async function readCredentialZip(bytes: Uint8Array): Promise<CredentialFiles> {
  if (bytes.byteLength > MAX_CREDENTIAL_ZIP_BYTES) {
    throw new Error(`Credential ZIP exceeds ${MAX_CREDENTIAL_ZIP_BYTES} bytes.`);
  }

  // Some archives include a ZIP64 footer even when the classic directory fields fit.
  const reader = new ZipReader(new Uint8ArrayReader(bytes), {
    strictness: "balanced",
    filenameValidation: "strict",
    checkLocalFilename: true,
    checkOverlappingEntry: true,
  });
  try {
    const entries: Partial<Record<keyof CredentialFiles, FileEntry>> = {};
    let count = 0;
    for await (const entry of reader.getEntriesGenerator()) {
      if (++count > MAX_ZIP_ENTRIES) {
        throw new Error(`Credential ZIP has more than ${MAX_ZIP_ENTRIES} entries.`);
      }
      if (entry.directory) continue;

      const basename = entry.filename.slice(entry.filename.lastIndexOf("/") + 1);
      const credential = CREDENTIAL_ENTRIES.find(({ filename }) => filename.test(basename));
      if (!credential) continue;
      if (entries[credential.role]) {
        throw new Error(`Credential ZIP has multiple ${credential.label} files.`);
      }
      entries[credential.role] = entry;
    }

    for (const { role, label } of CREDENTIAL_ENTRIES) {
      if (!entries[role]) throw new Error(`Credential ZIP is missing the ${label} file.`);
    }
    const { pikCert, pukCert, pukKeyPem } = entries as Record<keyof CredentialFiles, FileEntry>;
    return {
      pikCert: await readEntry(pikCert, CERT_BYTES),
      pukCert: await readEntry(pukCert, CERT_BYTES),
      pukKeyPem: await readEntry(pukKeyPem, MAX_PRIVATE_KEY_PEM_BYTES),
    };
  } finally {
    await reader.close();
  }
}

async function readEntry(entry: FileEntry, limit: number): Promise<Uint8Array> {
  if (entry.encrypted) {
    throw new Error("Expected an unencrypted credential ZIP.");
  }
  if (entry.uncompressedSize > limit) {
    throw new Error(`ZIP entry '${entry.filename}' exceeds ${limit} bytes.`);
  }

  const bytes = new Uint8Array(entry.uncompressedSize);
  let offset = 0;
  const writer = new WritableStream<Uint8Array>({
    write(chunk) {
      if (offset + chunk.length > bytes.length) {
        throw new Error(`ZIP entry '${entry.filename}' exceeds its declared uncompressed size.`);
      }
      bytes.set(chunk, offset);
      offset += chunk.length;
    },
  });
  await entry.getData(writer, { checkCrc32: true, useWebWorkers: false });
  if (offset !== bytes.length) {
    throw new Error(`ZIP entry '${entry.filename}' does not match its declared uncompressed size.`);
  }
  return bytes;
}
