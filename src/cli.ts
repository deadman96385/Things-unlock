#!/usr/bin/env node
import { webcrypto } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, unlink } from "node:fs/promises";
import { parseArgs } from "node:util";
import { CERT_BYTES, CHALLENGE_BYTES } from "./core/atx.js";
import { MAX_PRIVATE_KEY_PEM_BYTES } from "./core/pem.js";
import { MAX_CREDENTIAL_ZIP_BYTES } from "./import/zip.js";
import { createSigner, findMatches, parseChallenge, readCredentialZip } from "./index.js";
import type { UnlockBundle } from "./index.js";

const USAGE = `Usage:
  things-unlock sign --challenge <file> --bundle <zip> [--bundle <zip> ...] --out <file>
  things-unlock sign --challenge <file> --pik-cert <file> --puk-cert <file> --puk-key <pem> --out <file>

Generate an Android Things unlock credential from a 52-byte ATX challenge.
Choose a new output path and provide the credentials for the target product.
`;

async function main(args: string[]): Promise<void> {
  const [command, ...commandArgs] = args;
  if (command === undefined || command === "--help" || command === "-h") {
    process.stdout.write(USAGE);
    return;
  }
  if (command !== "sign") throw new Error(`Unknown command '${command}'. See --help.`);

  const { values } = parseArgs({
    args: commandArgs,
    options: {
      challenge: { type: "string" },
      bundle: { type: "string", multiple: true },
      "pik-cert": { type: "string" },
      "puk-cert": { type: "string" },
      "puk-key": { type: "string" },
      out: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (!values.challenge || !values.out) throw new Error("Specify --challenge and --out. See --help.");

  const pikPath = values["pik-cert"];
  const pukPath = values["puk-cert"];
  const keyPath = values["puk-key"];
  const zipPaths = values.bundle ?? [];
  if ((pikPath !== undefined || pukPath !== undefined || keyPath !== undefined) && !(pikPath && pukPath && keyPath)) {
    throw new Error("Loose credentials require --pik-cert, --puk-cert, and --puk-key together.");
  }
  if (zipPaths.length === 0 && !keyPath) throw new Error("Provide --bundle or a set of loose credential files.");

  const challengeBytes = await readFileWithinLimit(values.challenge, CHALLENGE_BYTES);
  const challenge = parseChallenge(challengeBytes);
  const signer = createSigner(webcrypto.subtle);
  const bundles: UnlockBundle[] = [];

  for (const path of zipPaths) {
    try {
      const files = await readCredentialZip(await readFileWithinLimit(path, MAX_CREDENTIAL_ZIP_BYTES));
      bundles.push(await signer.importBundle(files, path));
    } catch (error) {
      throw new Error(`Could not import ZIP '${path}': ${errorMessage(error)}`);
    }
  }
  if (pikPath && pukPath && keyPath) {
    const [pikCert, pukCert, pukKeyPem] = await Promise.all([
      readFileWithinLimit(pikPath, CERT_BYTES),
      readFileWithinLimit(pukPath, CERT_BYTES),
      readFileWithinLimit(keyPath, MAX_PRIVATE_KEY_PEM_BYTES),
    ]);
    bundles.push(await signer.importBundle({ pikCert, pukCert, pukKeyPem }, pukPath));
  }

  const matches = findMatches(challenge, bundles);
  if (!matches.length) {
    throw new Error(`No credential bundle matches product ID hash ${challenge.productIdHash}.`);
  }
  if (matches.length > 1) {
    const names = matches.map(({ name, keyVersion }) => `  ${name} (key version ${keyVersion})`).join("\n");
    throw new Error(`Multiple credential bundles match. Supply one of these bundles:\n${names}`);
  }

  const credential = await signer.createCredential(challengeBytes, matches[0]);
  await writeNewFile(values.out, credential);
  process.stdout.write(`Wrote ${credential.length} bytes to ${values.out}\n`);
}

async function readFileWithinLimit(path: string, limit: number): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of createReadStream(path, { end: limit })) {
    length += chunk.length;
    if (length > limit) throw new Error(`'${path}' exceeds ${limit} bytes.`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, length);
}

async function writeNewFile(path: string, bytes: Uint8Array): Promise<void> {
  const file = await open(path, "wx", 0o600);
  try {
    try {
      await file.writeFile(bytes);
    } finally {
      await file.close();
    }
  } catch (error) {
    await unlink(path).catch(() => {});
    throw error;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

main(process.argv.slice(2)).catch((error: unknown) => {
  process.stderr.write(`things-unlock: ${errorMessage(error)}\n`);
  process.exitCode = 1;
});
