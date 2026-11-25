import { createSigner, findMatches, parseChallenge, readCredentialZip } from "../src/index.js";
import type { CredentialFiles, UnlockBundle, UnlockChallenge } from "../src/index.js";
import { CERT_BYTES, CHALLENGE_BYTES } from "../src/core/atx.js";
import { MAX_PRIVATE_KEY_PEM_BYTES } from "../src/core/pem.js";
import { MAX_CREDENTIAL_ZIP_BYTES } from "../src/import/zip.js";
import { authorizedSourceUrl, directBundle, hasCredentialSources, MAX_MANIFEST_BYTES, parseSourceManifest } from "./credential-source.js";
import type { SourceBundle } from "./credential-source.js";
import { createDemo } from "./demo.js";
import { fetchSourceBytes } from "./source-fetch.js";

const CREDENTIAL_NAME = "unlock-credential.bin";
const SAMPLE_CREDENTIAL_NAME = "demo-unlock-credential.bin";

const subtle = globalThis.crypto?.subtle;
if (subtle) {
  initialize(createSigner(subtle));
} else {
  const notice = element("environment");
  notice.textContent = "Web Crypto is unavailable. Open this page over HTTPS or on localhost in a supported browser.";
  notice.hidden = false;
}

function initialize(signer: ReturnType<typeof createSigner>) {
  const clearButton = element<HTMLButtonElement>("clear-session");
  const demoButton = element<HTMLButtonElement>("try-demo");
  const demoFeedback = element("demo-feedback");
  const challengeInput = element<HTMLInputElement>("challenge-file");
  const challengeFeedback = element("challenge-feedback");
  const zipInput = element<HTMLInputElement>("zip-files");
  const zipMode = element<HTMLButtonElement>("zip-mode");
  const looseMode = element<HTMLButtonElement>("loose-mode");
  const sourceMode = element<HTMLButtonElement>("source-mode");
  sourceMode.hidden = !hasCredentialSources;
  const sourceInput = element<HTMLInputElement>("source-url");
  const loadSourceButton = element<HTMLButtonElement>("load-source");
  const sourceList = element("source-list");
  const sourceFeedback = element("source-feedback");
  const pikInput = element<HTMLInputElement>("pik-file");
  const pukInput = element<HTMLInputElement>("puk-file");
  const pemInput = element<HTMLInputElement>("pem-file");
  const addLooseButton = element<HTMLButtonElement>("add-loose");
  const importFeedback = element("import-feedback");
  const bundleList = element("bundle-list");
  const resultState = element("result-state");
  const matchStatus = element("match-status");
  const matchDescription = element("match-description");
  const matchOptions = element<HTMLFieldSetElement>("match-options");
  const matchChoices = element("match-choices");
  const downloadButton = element<HTMLButtonElement>("download");
  const outputFeedback = element("output-feedback");
  const downloadAgain = element<HTMLAnchorElement>("download-again");
  const verifyNext = element("verify-next");
  const looseInputs = [pikInput, pukInput, pemInput];
  const importControls = [challengeInput, zipInput, zipMode, looseMode, sourceMode, sourceInput, ...looseInputs];

  const bundles: UnlockBundle[] = [];
  let challenge: { name: string; bytes: Uint8Array; info: UnlockChallenge } | undefined;
  let chosenBundle: UnlockBundle | undefined;
  let downloadUrl: string | undefined;
  let demoMode = false;
  let sourceEntries: SourceBundle[] = [];
  let mode: "zip" | "loose" | "source" = "zip";
  let task: "challenge" | "import" | "sign" | "demo" | "source" | undefined;

  function currentMatches(): UnlockBundle[] {
    return challenge ? findMatches(challenge.info, bundles) : [];
  }

  function selectedMatch(matches: UnlockBundle[]): UnlockBundle | undefined {
    return matches.length === 1 ? matches[0] : matches.find((match) => match === chosenBundle);
  }

  function resetOutput() {
    if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    downloadUrl = undefined;
    downloadAgain.removeAttribute("href");
    downloadAgain.hidden = true;
    verifyNext.hidden = true;
    feedback(outputFeedback, "");
  }

  function renderMatch(matches: UnlockBundle[]) {
    const selected = selectedMatch(matches);
    element("challenge-details").hidden = !challenge;
    element("product-hash").textContent = challenge?.info.productIdHash ?? "";
    element("match-help").hidden = !challenge || bundles.length === 0 || matches.length > 0;

    if (selected) {
      showMatchStatus("match", "Product ID matches", bundleDescription(selected));
    } else if (!challenge) {
      showMatchStatus("idle", "Waiting for a challenge", "Add a challenge file to look up its product ID.");
    } else if (matches.length > 1) {
      showMatchStatus("idle", "Multiple bundles match", "Choose which matching bundle to use.");
    } else if (bundles.length) {
      showMatchStatus("missing", "No matching bundle", "Use the bundle issued for this product, or capture a challenge from the intended device.");
    } else {
      const formats = hasCredentialSources ? "Import a bundle from local files or an authorized URL."
        : "Import a ZIP bundle or a set of loose files.";
      showMatchStatus("idle", "Waiting for credentials", formats);
    }

    downloadButton.disabled = Boolean(task) || !selected;
    downloadButton.textContent = task === "sign" ? "Generating credential…" : "Generate & download";
  }

  function showMatchStatus(state: string, title: string, description: string) {
    resultState.dataset.state = state;
    matchStatus.textContent = title;
    matchDescription.textContent = description;
  }

  function renderBundleList(matches: UnlockBundle[]) {
    element("imported").hidden = bundles.length === 0;
    bundleList.replaceChildren(...bundles.map((bundle) => {
      const row = document.createElement("li");
      row.className = "bundle-row";
      const label = document.createElement("div");
      label.className = "bundle-label";
      const name = document.createElement("strong");
      name.textContent = bundle.name;
      const meta = document.createElement("span");
      meta.className = "bundle-meta";
      const matchesChallenge = matches.includes(bundle);
      meta.dataset.match = String(matchesChallenge);
      const matchLabel = matchesChallenge ? "Matches challenge" : "Different product";
      meta.textContent = "PUK version " + bundle.keyVersion + (challenge ? " · " + matchLabel : "");
      label.append(name, meta);
      row.append(label);
      if (demoMode) return row;

      const remove = document.createElement("button");
      remove.className = "button remove-bundle";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.setAttribute("aria-label", "Remove " + bundle.name);
      remove.disabled = Boolean(task);
      remove.addEventListener("click", () => {
        bundles.splice(bundles.indexOf(bundle), 1);
        if (chosenBundle === bundle) chosenBundle = undefined;
        resetOutput();
        feedback(importFeedback, "Removed " + bundle.name + ".");
        render();
        ({ zip: zipInput, loose: pikInput, source: sourceInput })[mode].focus();
      });
      row.append(remove);
      return row;
    }));
  }

  function renderChoices(matches: UnlockBundle[]) {
    matchOptions.hidden = matches.length < 2;
    matchOptions.disabled = Boolean(task);
    matchChoices.replaceChildren(...(matches.length > 1 ? matches.map((match) => {
      const label = document.createElement("label");
      label.className = "match-choice";
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = "bundle-choice";
      radio.checked = chosenBundle === match;
      radio.addEventListener("change", () => {
        chosenBundle = match;
        resetOutput();
        renderMatch(matches);
      });
      const name = document.createElement("span");
      name.textContent = bundleDescription(match);
      label.append(radio, name);
      return label;
    }) : []));
  }

  function render() {
    const busy = Boolean(task);
    const hasSource = Boolean(sourceInput.value.trim());
    const hasInputs = Boolean(challenge || bundles.length || hasSource || looseInputs.some((input) => input.files?.length));
    for (const control of importControls) control.disabled = busy || demoMode;
    zipMode.setAttribute("aria-pressed", String(mode === "zip"));
    looseMode.setAttribute("aria-pressed", String(mode === "loose"));
    sourceMode.setAttribute("aria-pressed", String(mode === "source"));
    element("zip-panel").hidden = mode !== "zip";
    element("loose-panel").hidden = mode !== "loose";
    element("source-panel").hidden = mode !== "source";
    loadSourceButton.disabled = busy || demoMode || !hasSource;
    addLooseButton.disabled = busy || demoMode || looseInputs.some((input) => !input.files?.length);
    clearButton.disabled = busy || !(hasInputs || demoFeedback.textContent || sourceFeedback.textContent
      || challengeFeedback.textContent || importFeedback.textContent || outputFeedback.textContent);
    clearButton.textContent = demoMode ? "Exit demo" : "Clear session";
    demoButton.disabled = busy || hasInputs;
    demoButton.textContent = task === "demo" ? "Generating sample files…" : "Try sample files";
    element("output-filename").textContent = demoMode ? SAMPLE_CREDENTIAL_NAME : CREDENTIAL_NAME;
    element("challenge-name").textContent = challenge?.name ?? "Drop a challenge file here";
    element("challenge-browse").textContent = challenge ? "Replace" : "Browse";

    const matches = currentMatches();
    renderSources();
    renderBundleList(matches);
    renderChoices(matches);
    renderMatch(matches);
  }

  function renderSources() {
    sourceList.hidden = sourceEntries.length === 0;
    sourceList.replaceChildren(...sourceEntries.map((entry, index) => {
      const row = document.createElement("li");
      row.className = "bundle-row";

      const label = document.createElement("div");
      label.className = "bundle-label";
      const title = document.createElement("strong");
      title.textContent = entry.name;
      const from = document.createElement("span");
      from.className = "bundle-meta";
      const locations = "zip" in entry.source ? [entry.source.zip] : Object.values(entry.source);
      const hosts = new Set(locations.map((url) => url.host));
      const declaredMatch = challenge && entry.productIdHash
        ? entry.productIdHash === challenge.info.productIdHash ? " · Listed product matches" : " · Listed for a different product"
        : "";
      from.textContent = [...hosts].join(", ") + declaredMatch;
      label.append(title, from);

      const button = document.createElement("button");
      button.type = "button";
      button.className = "button button-secondary";
      button.textContent = "Import";
      button.setAttribute("aria-label", "Import " + entry.name);
      button.disabled = Boolean(task) || demoMode;
      button.addEventListener("click", () => importSourceBundle(entry, index));
      row.append(label, button);
      return row;
    }));
  }

  async function perform(kind: NonNullable<typeof task>, message: HTMLElement, action: () => Promise<void>) {
    if (task) return;
    task = kind;
    render();
    try {
      await action();
    } catch (error) {
      feedback(message, errorText(error), "error");
    } finally {
      task = undefined;
      render();
    }
  }

  function loadChallenge(files: File[]) {
    void perform("challenge", challengeFeedback, async () => {
      challenge = undefined;
      chosenBundle = undefined;
      resetOutput();
      feedback(challengeFeedback, "");
      if (files.length !== 1) throw new Error("Choose one ATX challenge file.");
      const [file] = files;
      if (file.size !== CHALLENGE_BYTES) {
        throw new Error("Choose the " + CHALLENGE_BYTES + "-byte challenge.bin saved by fastboot. See How to capture it above.");
      }
      const bytes = await readFile(file, CHALLENGE_BYTES);
      try {
        challenge = { name: file.name, bytes, info: parseChallenge(bytes) };
      } catch (error) {
        throw new Error(errorText(error) + " Capture a fresh ATX challenge from your device.");
      }
    });
  }

  async function importFiles(files: CredentialFiles, name: string): Promise<UnlockBundle> {
    try {
      return await signer.importBundle(files, name);
    } finally {
      files.pukKeyPem.fill(0);
    }
  }

  async function importZip(bytes: Uint8Array, name: string): Promise<UnlockBundle> {
    try {
      return await importFiles(await readCredentialZip(bytes), name);
    } finally {
      bytes.fill(0);
    }
  }

  function loadZips(files: File[]) {
    void perform("import", importFeedback, async () => {
      feedback(importFeedback, "Importing ZIP bundles…");
      resetOutput();
      const failures: string[] = [];
      let count = 0;
      for (const file of files) {
        try {
          const bytes = await readFile(file, MAX_CREDENTIAL_ZIP_BYTES);
          bundles.push(await importZip(bytes, file.name));
          count++;
        } catch (error) {
          failures.push(file.name + " — " + errorText(error));
        }
      }
      const summary = count ? "Imported " + count + (count === 1 ? " bundle." : " bundles.") : "";
      if (failures.length) failures.push("Try the original credential ZIP or import the three files as loose credentials.");
      feedback(importFeedback, [summary, ...failures].filter(Boolean).join("\n"), failures.length ? "error" : "success");
    });
  }

  function loadLoose() {
    const pik = pikInput.files?.[0];
    const puk = pukInput.files?.[0];
    const pem = pemInput.files?.[0];
    if (!(pik && puk && pem)) return;

    void perform("import", importFeedback, async () => {
      feedback(importFeedback, "Importing loose credentials…");
      resetOutput();
      const [pikCert, pukCert] = await Promise.all([readFile(pik, CERT_BYTES), readFile(puk, CERT_BYTES)]);
      const pukKeyPem = await readFile(pem, MAX_PRIVATE_KEY_PEM_BYTES);
      try {
        bundles.push(await importFiles({ pikCert, pukCert, pukKeyPem }, puk.name));
      } catch (error) {
        throw new Error(errorText(error) + " Select both certificates and the PEM from the same credential set.");
      }
      for (const input of looseInputs) input.value = "";
      feedback(importFeedback, "Imported " + puk.name + ".", "success");
    });
  }

  function loadSource() {
    void perform("source", sourceFeedback, async () => {
      sourceEntries = [];
      renderSources();
      feedback(sourceFeedback, "Loading source…");
      const url = authorizedSourceUrl(sourceInput.value.trim());
      const path = url.pathname.toLowerCase();
      if (path.endsWith(".zip")) {
        sourceEntries = [directBundle(url)];
      } else if (path.endsWith(".json") || path.endsWith(".txt")) {
        const bytes = await fetchSourceBytes(url, MAX_MANIFEST_BYTES);
        try {
          const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
          sourceEntries = parseSourceManifest(text, url);
        } finally {
          bytes.fill(0);
        }
      } else {
        throw new Error("Use a URL to a .json or .txt manifest or a .zip bundle.");
      }
      feedback(sourceFeedback, "Choose a bundle to import.");
    });
  }

  function importSourceBundle(entry: SourceBundle, index: number) {
    void perform("source", sourceFeedback, async () => {
      feedback(sourceFeedback, "Downloading the selected bundle…");
      const { source, name } = entry;
      let bundle: UnlockBundle;
      if ("zip" in source) {
        bundle = await importZip(await fetchSourceBytes(source.zip, MAX_CREDENTIAL_ZIP_BYTES), name);
      } else {
        const [pikCert, pukCert] = await Promise.all([
          fetchSourceBytes(source.pikCert, CERT_BYTES),
          fetchSourceBytes(source.pukCert, CERT_BYTES),
        ]);
        const pukKeyPem = await fetchSourceBytes(source.pukKey, MAX_PRIVATE_KEY_PEM_BYTES);
        bundle = await importFiles({ pikCert, pukCert, pukKeyPem }, name);
      }
      if (entry.productIdHash && entry.productIdHash !== bundle.productIdHash) {
        throw new Error("The imported bundle’s product ID differs from the manifest.");
      }
      bundles.push(bundle);
      sourceEntries.splice(index, 1);
      resetOutput();
      feedback(sourceFeedback, "Imported " + name + ".", "success");
    });
  }

  bindFilePicker(challengeInput, element("challenge-drop"), loadChallenge);
  bindFilePicker(zipInput, element("zip-drop"), loadZips);
  for (const input of looseInputs) input.addEventListener("change", render);
  addLooseButton.addEventListener("click", loadLoose);
  zipMode.addEventListener("click", () => { mode = "zip"; render(); });
  looseMode.addEventListener("click", () => { mode = "loose"; render(); });
  sourceMode.addEventListener("click", () => { mode = "source"; render(); });
  loadSourceButton.addEventListener("click", loadSource);
  sourceInput.addEventListener("input", () => {
    sourceEntries = [];
    feedback(sourceFeedback, "");
    render();
  });
  sourceInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !loadSourceButton.disabled) loadSource();
  });

  demoButton.addEventListener("click", () => {
    void perform("demo", demoFeedback, async () => {
      feedback(challengeFeedback, "");
      feedback(importFeedback, "");
      resetOutput();
      feedback(demoFeedback, "Generating temporary demo keys in this browser…");
      const { challenge: bytes, files } = await createDemo(globalThis.crypto);
      const info = parseChallenge(bytes);
      const bundle = await importFiles(files, "Generated sample credentials");
      challenge = { name: "sample-challenge.bin", bytes, info };
      bundles.push(bundle);
      mode = "zip";
      demoMode = true;
      feedback(demoFeedback, "Demo active. The sample credential is for practice. Select Exit demo to use your own files.", "success");
      element("challenge-drop").scrollIntoView({ block: "nearest" });
    });
  });

  downloadButton.addEventListener("click", () => {
    const match = selectedMatch(currentMatches());
    const input = challenge;
    if (!(input && match)) return;

    void perform("sign", outputFeedback, async () => {
      resetOutput();
      feedback(outputFeedback, "Signing in this browser…");
      const credential = await signer.createCredential(input.bytes, match);
      downloadUrl = URL.createObjectURL(new Blob([credential], { type: "application/octet-stream" }));
      downloadAgain.href = downloadUrl;
      downloadAgain.download = demoMode ? SAMPLE_CREDENTIAL_NAME : CREDENTIAL_NAME;
      downloadAgain.hidden = false;
      downloadAgain.click();
      verifyNext.hidden = demoMode;
      const label = demoMode ? "Demo credential generated" : "Credential generated";
      feedback(outputFeedback, label + " · " + credential.length.toLocaleString() + " bytes", "success");
    });
  });

  clearButton.addEventListener("click", () => {
    const wasDemo = demoMode;
    challenge = undefined;
    chosenBundle = undefined;
    bundles.length = 0;
    for (const input of looseInputs) input.value = "";
    sourceInput.value = "";
    sourceEntries = [];
    mode = "zip";
    demoMode = false;
    resetOutput();
    feedback(challengeFeedback, "");
    feedback(importFeedback, "");
    feedback(sourceFeedback, "");
    feedback(demoFeedback, "");
    render();
    (wasDemo ? demoButton : challengeInput).focus();
  });

  for (const eventName of ["dragover", "drop"]) {
    document.addEventListener(eventName, (event) => {
      if ((event as DragEvent).dataTransfer?.types.includes("Files")) event.preventDefault();
    });
  }
  render();
}

function bundleDescription(bundle: UnlockBundle): string {
  return bundle.name + " · PUK version " + bundle.keyVersion;
}

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const result = document.getElementById(id);
  if (!result) throw new Error("Missing UI element " + id);
  return result as T;
}

function bindFilePicker(input: HTMLInputElement, dropZone: HTMLElement, onFiles: (files: File[]) => void) {
  input.addEventListener("change", () => {
    const files = Array.from(input.files ?? []);
    input.value = "";
    if (files.length) onFiles(files);
  });
  dropZone.addEventListener("dragover", (event) => {
    if (input.disabled || !event.dataTransfer?.types.includes("Files")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    dropZone.dataset.dragging = "";
  });
  dropZone.addEventListener("dragleave", (event) => {
    if (!(event.relatedTarget instanceof Node && dropZone.contains(event.relatedTarget))) {
      delete dropZone.dataset.dragging;
    }
  });
  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    delete dropZone.dataset.dragging;
    const files = Array.from(event.dataTransfer?.files ?? []);
    if (!input.disabled && files.length) onFiles(files);
  });
}

async function readFile(file: File, maxBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  if (file.size > maxBytes) {
    throw new Error("File exceeds " + maxBytes.toLocaleString() + " bytes.");
  }
  return new Uint8Array(await file.arrayBuffer());
}

function feedback(element: HTMLElement, text: string, tone = "") {
  element.textContent = text;
  element.dataset.tone = tone;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
