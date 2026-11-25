export interface SourceFetchRequest {
  url: string;
  limit: number;
}

export type SourceFetchResult = { bytes: Uint8Array<ArrayBuffer> } | { error: string };

export async function fetchSourceBytes(url: URL, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  const worker = new Worker(new URL("./source-worker.js", import.meta.url), { type: "module" });
  let timeout: number | undefined;
  try {
    return await new Promise((resolve, reject) => {
      worker.addEventListener("message", (event: MessageEvent<SourceFetchResult>) => {
        if ("bytes" in event.data) resolve(event.data.bytes);
        else reject(new Error(event.data.error));
      }, { once: true });
      worker.addEventListener("error", () => reject(new Error("The browser could not start the source importer.")), { once: true });
      timeout = window.setTimeout(() => reject(new Error("The source request timed out. Try the URL again.")), 17_000);
      worker.postMessage({ url: url.href, limit } satisfies SourceFetchRequest);
    });
  } finally {
    window.clearTimeout(timeout);
    worker.terminate();
  }
}
