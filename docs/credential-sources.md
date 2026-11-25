# Credential sources

Use one manifest to list the authorized credential bundles for several devices. The page downloads only the bundle the user selects and signs in the browser.

## Lay out the source folder

Put the manifest at the top of a folder on your HTTPS host. Give each device its own subfolder. This example assumes the folder is served at `https://credentials.example/atx/`. Replace that address with your own source root.

```text
atx/
├── bundles.json
├── bundles.txt
└── boards/
    ├── board-a/
    │   └── credentials.zip
    ├── board-b/
    │   └── credentials.zip
    └── board-c/
        ├── pik.bin
        ├── puk.bin
        └── puk.pem
```

## Create the manifest

Choose JSON for named devices or loose files. Choose TXT for a list of ZIPs. Save the chosen file as UTF-8.

### JSON

Put one entry per device in the `bundles` array. Each entry needs a `name` and either a `zip` path or a `files` object containing the PIK certificate, PUK certificate, and PUK private key.

```json
{
  "version": 1,
  "bundles": [
    {
      "name": "Board A",
      "zip": "boards/board-a/credentials.zip"
    },
    {
      "name": "Board B",
      "zip": "boards/board-b/credentials.zip"
    },
    {
      "name": "Board C",
      "files": {
        "pikCert": "boards/board-c/pik.bin",
        "pukCert": "boards/board-c/puk.bin",
        "pukKey": "boards/board-c/puk.pem"
      }
    }
  ]
}
```

To add another device, upload its files in a new subfolder and append an entry to `bundles`. For a match preview, add `productIdHash` to that entry. Load a challenge from that device in Things Unlock and copy the displayed **Product ID hash**. The field takes 64 hexadecimal characters. The page uses it to flag a match before download and checks it against the imported PUK certificate.

### TXT

List one ZIP path or URL per line. Blank lines and lines beginning with `#` are ignored.

```text
# Board A and Board B
boards/board-a/credentials.zip
boards/board-b/credentials.zip
```

## Enable URL imports on GitHub Pages

1. In the **Things Unlock repository**, go to **Settings → Secrets and variables → Actions → Variables → New repository variable**. Name it `THINGS_UNLOCK_CREDENTIAL_ROOTS` and set its value to the source folder URL, for example `https://credentials.example/atx/`. Include the trailing slash. Use commas between roots if you have several. [GitHub repository variables](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-variables#creating-configuration-variables-for-a-repository)
2. Open **Actions → Deploy Things Unlock → Run workflow**, select the default branch, and run the workflow. The new build shows **From URL** when a source root is configured. [Running a GitHub Actions workflow](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
3. On the deployed site, open **Signing credentials → From URL**, paste `https://credentials.example/atx/bundles.json` with your own host substituted, and select **Load source**. Select **Import** next to the device you want. A direct `.zip` URL also works for a single bundle.

For a local PowerShell build, set the same variable before running the build.

```powershell
$env:THINGS_UNLOCK_CREDENTIAL_ROOTS = 'https://credentials.example/atx/'
npm run build:web
```

Once a source root is configured, changes to its hosted manifest and bundle files are picked up the next time someone loads the manifest. Changing the source root requires a new build.

## Source requirements

- Relative paths resolve from the manifest’s folder. For a ZIP next to the manifest, use its filename. Absolute HTTPS URLs also work inside configured source folders.
- Each manifest must list between 1 and 200 bundles and fit within 128 KiB.
- The manifest and credential files need direct HTTPS URLs that allow cross-origin requests from the app. Use raw file URLs for authorized GitHub-hosted files. Restricted objects can use short-lived signed URLs for each file.
- Configured folder URLs are visible in the built app. Put only folder URLs in `THINGS_UNLOCK_CREDENTIAL_ROOTS`. Keep private key material and access tokens in your credential store.
