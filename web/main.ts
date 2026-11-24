import { createSigner, findMatches, parseChallenge, readCredentialZip } from "../src/index.js";
import type { UnlockBundle, UnlockChallenge } from "../src/index.js";
import { CERT_BYTES, CHALLENGE_BYTES } from "../src/core/atx.js";
import { MAX_PRIVATE_KEY_PEM_BYTES } from "../src/core/pem.js";
import { MAX_CREDENTIAL_ZIP_BYTES } from "../src/import/zip.js";
import demoFixture from "./demo-fixture.json" with { type: "json" };

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
  const importControls = [challengeInput, zipInput, zipMode, looseMode, ...looseInputs];

  const bundles: UnlockBundle[] = [];
  let challenge: { name: string; bytes: Uint8Array; info: UnlockChallenge } | undefined;
  let chosenBundle: UnlockBundle | undefined;
  let downloadUrl: string | undefined;
  let demoMode = false;
  let mode: "zip" | "loose" = "zip";
  let task: "challenge" | "import" | "sign" | "demo" | undefined;

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
      showMatchStatus("idle", "Waiting for credentials", "Import a ZIP bundle or a set of loose files.");
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
        (mode === "zip" ? zipInput : pikInput).focus();
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
    const hasInputs = Boolean(challenge || bundles.length || looseInputs.some((input) => input.files?.length));
    for (const control of importControls) control.disabled = busy || demoMode;
    zipMode.setAttribute("aria-pressed", String(mode === "zip"));
    looseMode.setAttribute("aria-pressed", String(mode === "loose"));
    element("zip-panel").hidden = mode !== "zip";
    element("loose-panel").hidden = mode !== "loose";
    addLooseButton.disabled = busy || demoMode || looseInputs.some((input) => !input.files?.length);
    clearButton.disabled = busy || !(hasInputs || demoFeedback.textContent
      || challengeFeedback.textContent || importFeedback.textContent || outputFeedback.textContent);
    clearButton.textContent = demoMode ? "Exit demo" : "Clear session";
    demoButton.disabled = busy || hasInputs;
    demoButton.textContent = task === "demo" ? "Loading sample files…" : "Try sample files";
    element("output-filename").textContent = demoMode ? SAMPLE_CREDENTIAL_NAME : CREDENTIAL_NAME;
    element("challenge-name").textContent = challenge?.name ?? "Drop a challenge file here";
    element("challenge-browse").textContent = challenge ? "Replace" : "Browse";

    const matches = currentMatches();
    renderBundleList(matches);
    renderChoices(matches);
    renderMatch(matches);
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

  async function importZip(bytes: Uint8Array, name: string): Promise<UnlockBundle> {
    try {
      const credentials = await readCredentialZip(bytes);
      try {
        return await signer.importBundle(credentials, name);
      } finally {
        credentials.pukKeyPem.fill(0);
      }
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
        bundles.push(await signer.importBundle({ pikCert, pukCert, pukKeyPem }, puk.name));
      } catch (error) {
        throw new Error(errorText(error) + " Select both certificates and the PEM from the same credential set.");
      } finally {
        pukKeyPem.fill(0);
      }
      for (const input of looseInputs) input.value = "";
      feedback(importFeedback, "Imported " + puk.name + ".", "success");
    });
  }

  bindFilePicker(challengeInput, element("challenge-drop"), loadChallenge);
  bindFilePicker(zipInput, element("zip-drop"), loadZips);
  for (const input of looseInputs) input.addEventListener("change", render);
  addLooseButton.addEventListener("click", loadLoose);
  zipMode.addEventListener("click", () => { mode = "zip"; render(); });
  looseMode.addEventListener("click", () => { mode = "loose"; render(); });

  demoButton.addEventListener("click", () => {
    void perform("demo", demoFeedback, async () => {
      feedback(challengeFeedback, "");
      feedback(importFeedback, "");
      resetOutput();
      const bytes = decodeDemoBytes(demoFixture.challenge);
      const info = parseChallenge(bytes);
      const bundle = await importZip(decodeDemoBytes(demoFixture.bundle), "sample-credentials.zip");
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
    mode = "zip";
    demoMode = false;
    resetOutput();
    feedback(challengeFeedback, "");
    feedback(importFeedback, "");
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

function decodeDemoBytes(chunks: readonly string[]): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(chunks.join("")), (character) => character.charCodeAt(0));
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
