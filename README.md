# SFDCAutoCert

Salesforce certificate discovery, **usage mapping** and risk audit. Phase 1 of an automated certificate lifecycle tool.

All Salesforce calls are made **server-side** (Metadata API SOAP from the backend). Nothing runs in the browser,
so no CORS configuration is needed on the Connected App; a future UI should talk only to this backend.

## Phase 1: inventory & display
    python scripts/setup_connected_app.py <sf-alias> <username>        # once: External Client App + JWT key in .secrets/
    python -m sfdcautocert serve --config .secrets/org.json            # dashboard on http://127.0.0.1:8765/cert-manager

`.secrets/org.json`: `{"client_id": "...", "username": "...", "key_file": "jwt_key.pem"}` (key path is relative to the file; git-ignored).
For dev you can also use `serve <sf-alias>` (reuses the sf CLI login).

The browser only talks to this backend (`/api/inventory`, `POST /api/refresh`); every Salesforce call is made server-side,
so no CORS setup is needed on the app. The dashboard shows relevance tiles (Action / Watch / Cleanup / Not affected), certificates
and discovered endpoints, with per-item details (subject, EKU, usages, findings, trust). Scans run in the background (~50s).

## Scan scopes
| Scope | Reads | Typical time |
|---|---|---|
| **standard** (default) | certificates, SAML SSO, Connected Apps, Named/External Credentials, Auth Providers, External Data Sources, Flows, org Settings (Identity Provider), Remote Site / CSP | ~30s |
| **apex** | + Apex classes/triggers that mention certificates, callouts or URLs | ~30s |
| **all** | + Sites and Experience Cloud networks | ~30s |

Apex `Body` cannot be filtered in SOQL/SOSL, so the Apex scan lists classes cheaply, pulls bodies in batches of 25 through the Tooling API
and keeps only the relevant ones (managed-package classes are skipped); memory stays flat even for large orgs.
Without an Apex scan a certificate with no references is shown as WATCH (not CLEANUP), because Apex may still use it.
CLI: `salesforce --scope standard|apex|all`; the dashboard has a scope selector next to *Rescan org*.

## Layout (where phase 2 plugs in)
    sf/            Salesforce clients: auth (JWT bearer / sf CLI), Metadata API retrieve+deploy, Tooling API
    sources.py     certificates from files / Metadata blobs, TLS endpoint scan
    usage.py       certificate -> component mapping       discovery.py   endpoints referenced by the org
    analyze.py     findings per certificate               relevance.py   triage level + reason
    service.py     scan_org(), Inventory (cached snapshot, refresh)
    api.py + static/index.html   FastAPI router (login session, scan jobs, inventory) + dashboard
    apex.py        bounded Apex scan
    certstore.py rotate.py acme.py issue.py   phase 2 actions (CSR flow, rotation, issuance) - already usable, not wired to the UI

## Run
    pip install -r requirements.txt
    python -m sfdcautocert --out out salesforce <sf-alias>     # dev: reuses sf CLI login
    python -m sfdcautocert --out out salesforce --jwt-client-id <key> --jwt-username <user> --jwt-key key.pem   # headless
    python -m sfdcautocert endpoints --sf-defaults host:8443
    python -m sfdcautocert files ./certs
    python -m unittest discover -s tests

JWT bearer env vars: `SF_CLIENT_ID`, `SF_USERNAME`, `SF_JWT_KEY_FILE`, `SF_LOGIN_URL`. (JWT path is not yet exercised against a real Connected App.)

## Usage mapping (`usage.py`)
Retrieves SamlSsoConfig, ConnectedApp, NamedCredential, ExternalCredential, AuthProvider, ExternalDataSource, ApexClass, ApexTrigger
and links each certificate to the components that reference it:

| Evidence | Meaning |
|---|---|
| exact | an XML field equals the cert DeveloperName/label (field-name agnostic) |
| pem | the cert PEM is embedded in a component (e.g. Connected App JWT cert) |
| text | DeveloperName appears as a whole token in Apex source |

**Risk score (0-100)** = urgency (days left, dual-use/weak crypto) x blast radius (SAML SSO 100, Connected App 80,
Named/External Credential & Auth Provider 70, Data Source/Apex 50). Certs with no references get `UNUSED` (LOW).

Limits: org-level uses outside the scanned types (Identity Provider, My Domain, Experience Cloud) are not detected yet.

## Findings
EXPIRED / EXPIRES_SOON, DUAL_USE (CRITICAL on public CA, INFO on self-signed), NO_EKU, LONG_LIFETIME (>47d),
WEAK_KEY, WEAK_SIG, UNTRUSTED_CHAIN (vs Mozilla set), UNREACHABLE, UNUSED.

## Issuance (acme.py / issue.py)
RFC 8555 client (ES256 account, http-01 built-in, dns-01 via hook command), CA agnostic. `issue.issue()` generates the key + CSR,
runs the order, and **enforces purpose**: the issued EKU must be exactly `clientAuth` (or `serverAuth`), otherwise it refuses to deploy.
`renewal_due()` renews at ~1/3 lifetime left (47d cert -> ~day 31); `backoff_seconds()` is the CA-failure retry schedule.
Tested against an in-process fake ACME CA (signature/nonce/key-authorization verification). Not yet run against a real CA.

## Relevance triage (relevance.py, discovery.py)
Every item gets ACTION / WATCH / CLEANUP / NOT_AFFECTED with a reason: system-managed certs (Tooling API) and self-signed/private-CA
certs are out of scope of the public-CA changes; dual-use on public CA, weak crypto, in-use+expiring, and untrusted/unreachable endpoints are ACTION.
`discovery.py` extracts endpoints from RemoteSiteSetting, CspTrustedSite, NamedCredential, ExternalDataSource, AuthProvider, Apex and Flows,
then TLS-scans them (root CA, Mozilla trust, EKU). Third-party server-cert findings are INFO (not actionable by the org owner).

## Headless auth
`scripts/setup_connected_app.py <alias> <user>` creates an External Client App (new Connected Apps are blocked in many orgs),
JWT bearer + API scope, pre-authorised through a permission set. Verified end to end on the dev org; no browser/CORS involved.

## Installing certificates into Salesforce: the CSR flow (certstore.py, rotate.py) - VERIFIED
Metadata API cannot import an externally issued cert + key (PEM+key, PKCS12 and plain cert are all replaced by a Salesforce-generated
self-signed cert). The CSR flow works, end to end, server-side:

1. deploy `Certificate` with `caSigned=true` -> retrieve returns a **CSR** (`BEGIN CERTIFICATE REQUEST`); cert is `Unusable` until signed
2. sign the CSR with your CA
3. deploy the signed chain under the same name -> cert becomes usable; expiry/EKU come from the signed cert; the **private key never leaves Salesforce**

`certstore.request_csr / fetch_csr / install_signed` implement this (install refuses a leaf whose key differs from the pending CSR).
`rotate.rotate()` creates `<Name>_<YYYYMMDD>` beside the old cert (overlap), gets it signed by a pluggable `Signer`
(`CommandSigner` wraps any CLI: Vault PKI, AWS Private CA, step-ca, ADCS), enforces purpose, and installs it.
Live check: `python scripts/csr_e2e.py <consumer-key> <username>`.

**Constraints found**
- The Salesforce CSR is fixed: `CN=<DeveloperName>`, `SAN=DNS:<DeveloperName>` (no dots allowed), RSA 2048. We cannot request a real domain.
  Public ACME CAs validate domain names, so they will not sign it. Use a private CA that signs the CSR under your policy
  (the ACME client in `acme.py` is for server certs on your own hosts / ACME-capable private CAs).
- Public CAs no longer issue `clientAuth`, so mTLS client certs need a private PKI anyway.
- Rotation creates a new cert; repointing consumers (Named Credential, SAML config, ...) and retiring the old one is the next step.

## Hosting inside salesforce-debugtool (Heroku)
`app.py` includes `create_router(base="/cert-manager")` (guarded import). The page is the OAuth redirect target, so register
`https://<app>.herokuapp.com/cert-manager` as a Callback URL on the Connected App named by `SF_CLIENT_ID` (scope `api`).
The user's token is exchanged for an in-memory, HttpOnly session; every Salesforce call is made server-side.
Hosted-mode guards: Salesforce-only instance URLs, no TLS probing of private addresses, `X-Requested-With` on POSTs.
Install from the private repo with a read-only token: `git+https://${SFDCAUTOCERT_GH_TOKEN}@github.com/gambacloud/sfdcautocert.git@<sha>`.
