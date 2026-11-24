import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js/lib/zip-native.js";
import { build } from "esbuild";

const [bundle, template, styles, instructions, metadata] = await Promise.all([
  build({
    entryPoints: ["web/main.ts"],
    outfile: "dist-web/assets/main.js",
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    minify: true,
    legalComments: "eof",
    write: false,
  }),
  readFile("web/index.html", "utf8"),
  readFile("web/styles.css"),
  readFile("web/OFFLINE.txt"),
  readFile("package.json", "utf8"),
]);

const { version } = JSON.parse(metadata);
const offlineName = "things-unlock-v" + version + "-offline.zip";
const checksumName = offlineName + ".sha256";
const sourceLocation = process.env.THINGS_UNLOCK_SOURCE_URL;
let sourceLink = "";
if (sourceLocation) {
  const sourceUrl = new URL(sourceLocation);
  if (sourceUrl.protocol !== "https:") throw new Error("The source link must use HTTPS.");
  const href = sourceUrl.href.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
  sourceLink = '<a href="' + href + '">Source for this build</a>';
}

const page = template.replace("<!-- source-link -->", sourceLink);
const website = page.replace("<!-- offline-links -->",
  '<a download href="./downloads/' + offlineName + '">Offline ZIP</a>' +
  '<a download href="./downloads/' + checksumName + '">SHA-256</a>');
const assets = [
  ["assets/main.js", bundle.outputFiles[0].contents],
  ["assets/styles.css", styles],
];

const archive = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
const lastModDate = new Date("2020-01-01T12:00:00Z");
for (const [path, bytes] of [
  ["index.html", Buffer.from(page.replace("<!-- offline-links -->", ""))],
  ["START-HERE.txt", instructions],
  ...assets,
]) {
  await archive.add(path, new Uint8ArrayReader(bytes), { lastModDate, extendedTimestamp: false });
}
const zip = await archive.close();
const checksum = createHash("sha256").update(zip).digest("hex");

await Promise.all([
  mkdir("dist-web/assets", { recursive: true }),
  mkdir("dist-web/downloads", { recursive: true }),
]);
await Promise.all([
  writeFile("dist-web/index.html", website),
  writeFile("dist-web/downloads/" + offlineName, zip),
  writeFile("dist-web/downloads/" + checksumName, checksum + "  " + offlineName + "\n"),
  ...assets.map(([path, bytes]) => writeFile("dist-web/" + path, bytes)),
]);
