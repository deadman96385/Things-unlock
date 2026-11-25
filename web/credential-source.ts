declare const __CREDENTIAL_SOURCE_ROOTS__: string[];

const credentialSourceRoots = __CREDENTIAL_SOURCE_ROOTS__.map((root) => new URL(root));
export const hasCredentialSources = credentialSourceRoots.length > 0;
export const MAX_MANIFEST_BYTES = 128 * 1024;
const MAX_ENTRIES = 200;

export interface SourceBundle {
  name: string;
  productIdHash?: string;
  source: { zip: URL } | { pikCert: URL; pukCert: URL; pukKey: URL };
}

export function authorizedSourceUrl(input: string, base?: URL): URL {
  let url: URL;
  try {
    url = new URL(input, base);
  } catch {
    throw new Error("Enter a valid HTTPS source URL.");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || /%(2f|5c|25)/i.test(url.pathname)) {
    throw new Error("Use an HTTPS URL without embedded credentials, fragments, or encoded path separators.");
  }
  if (!credentialSourceRoots.some((root) => root.origin === url.origin && url.pathname.startsWith(root.pathname))) {
    throw new Error("This URL is outside the credential folders configured for this build.");
  }
  return url;
}

export function directBundle(url: URL): SourceBundle {
  return { name: decodeURIComponent(url.pathname.split("/").pop() || "Credential ZIP"), source: { zip: url } };
}

export function parseSourceManifest(text: string, manifestUrl: URL): SourceBundle[] {
  if (manifestUrl.pathname.toLowerCase().endsWith(".txt")) {
    const entries = text.split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
    checkCount(entries);
    return entries.map((path) => directBundle(bundleUrl(path, manifestUrl, ".zip")));
  }

  let manifest: unknown;
  try {
    manifest = JSON.parse(text);
  } catch {
    throw new Error("The source did not return valid JSON.");
  }
  if (!isRecord(manifest) || manifest.version !== 1 || !Array.isArray(manifest.bundles)) {
    throw new Error("Use a version 1 manifest with a bundles array.");
  }
  checkCount(manifest.bundles);
  return manifest.bundles.map((entry, index) => {
    try {
      return parseBundle(entry, manifestUrl);
    } catch (error) {
      throw new Error("Manifest bundle " + (index + 1) + " · " + (error as Error).message);
    }
  });
}

function parseBundle(entry: unknown, base: URL): SourceBundle {
  if (!isRecord(entry) || typeof entry.name !== "string" || !entry.name.trim() || entry.name.length > 120) {
    throw new Error("Provide a bundle name of up to 120 characters.");
  }
  let productIdHash: string | undefined;
  if (entry.productIdHash !== undefined) {
    if (typeof entry.productIdHash !== "string" || !/^[0-9a-f]{64}$/i.test(entry.productIdHash)) {
      throw new Error("A product ID hash must be 64 hexadecimal characters.");
    }
    productIdHash = entry.productIdHash.toLowerCase();
  }

  if (entry.zip !== undefined && entry.files === undefined) {
    return { name: entry.name.trim(), productIdHash, source: { zip: bundleUrl(entry.zip, base, ".zip") } };
  }
  if (entry.zip === undefined && isRecord(entry.files)) {
    const { pikCert, pukCert, pukKey } = entry.files;
    return {
      name: entry.name.trim(),
      productIdHash,
      source: {
        pikCert: bundleUrl(pikCert, base, ".bin"),
        pukCert: bundleUrl(pukCert, base, ".bin"),
        pukKey: bundleUrl(pukKey, base, ".pem"),
      },
    };
  }
  throw new Error("Provide either a ZIP path or three loose credential files.");
}

function bundleUrl(path: unknown, base: URL, extension: string): URL {
  if (typeof path !== "string" || !path.trim()) throw new Error("A bundle file path is missing.");
  const url = authorizedSourceUrl(path.trim(), base);
  if (!url.pathname.toLowerCase().endsWith(extension)) {
    throw new Error("Expected a file path ending in " + extension + ".");
  }
  return url;
}

function checkCount(entries: readonly unknown[]) {
  if (entries.length === 0 || entries.length > MAX_ENTRIES) {
    throw new Error("List between 1 and " + MAX_ENTRIES + " credential bundles.");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
