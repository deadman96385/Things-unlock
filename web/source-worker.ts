import { authorizedSourceUrl } from "./credential-source.js";
import type { SourceFetchRequest, SourceFetchResult } from "./source-fetch.js";

self.addEventListener("message", async (event: MessageEvent<SourceFetchRequest>) => {
  try {
    const url = authorizedSourceUrl(event.data.url);
    const bytes = await fetchBounded(url, event.data.limit);
    self.postMessage({ bytes } satisfies SourceFetchResult, { transfer: [bytes.buffer] });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not read the source.";
    self.postMessage({ error: message } satisfies SourceFetchResult, {});
  }
});

async function fetchBounded(url: URL, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024 * 1024) {
    throw new Error("Invalid source download limit.");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        mode: "cors",
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
    } catch {
      throw new Error("Could not reach the source. Check that the URL is current, allows browser requests, and leads directly to the file.");
    }
    if (!response.ok) throw new Error("The source returned HTTP " + response.status + ".");
    if (Number(response.headers.get("content-length")) > limit) {
      throw new Error("The source file exceeds " + limit.toLocaleString() + " bytes.");
    }
    if (!response.body) throw new Error("The source returned an empty file.");

    const bytes = new Uint8Array(limit);
    const reader = response.body.getReader();
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        try {
          if (length + value.length > limit) throw new Error("The source file exceeds " + limit.toLocaleString() + " bytes.");
          bytes.set(value, length);
          length += value.length;
        } finally {
          value.fill(0);
        }
      }
      if (length === 0) throw new Error("The source returned an empty file.");
      return bytes.subarray(0, length);
    } catch (error) {
      bytes.fill(0);
      throw error;
    } finally {
      reader.releaseLock();
    }
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}
