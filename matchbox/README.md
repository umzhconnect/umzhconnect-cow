# matchbox — FHIR Mapping Language transformation service

[Matchbox](https://github.com/ahdis/matchbox) (ahdis, Apache-2.0) is a HAPI-based
FHIR server that runs the official HL7 **FHIR Mapping Language / StructureMap**
engine. In this deployment it is the transformation step of the
referral-reception workflow: it converts a placer's FHIR Bundle into the Swiss
**CH eToC** (`ch.fhir.ig.ch-etoc`) profile via the standard
`StructureMap/$transform` operation, keeping the Kestra flow a thin orchestrator
with no embedded mapping code.

## Endpoint

```
POST http://matchbox:8080/matchboxv3/fhir/StructureMap/$transform?source=<StructureMap canonical URL>
Content-Type: application/fhir+json
Accept:       application/fhir+json

<source Bundle>            →  200  <transformed CH eToC Bundle>
```

The `source` query parameter is the **canonical URL** of the StructureMap to
run (the workflow's `ETOC_STRUCTUREMAP_URL`).

> **CH eToC ships no StructureMap.** `ch.fhir.ig.ch-etoc` (3.0.1) defines the
> target **profiles only**. The referral transform is therefore a **custom map
> you author** in FHIR Mapping Language against those profiles — not an IG
> artifact. Give it a canonical under a namespace you own (e.g.
> `http://umzhconnect.ch/fhir/StructureMap/ServiceRequestBundleToChEtoc`), and
> load it into matchbox one of two ways:
>
> - **POST the source once:** `POST /matchboxv3/fhir/StructureMap` with
>   `Content-Type: text/fhir-mapping` and the `.map`/`.fml` body — matchbox
>   compiles it to a StructureMap and serves it under its declared canonical.
>   (With a persistent `/database`, it survives restarts — see below.)
> - **Ship it in an IG package** you also list in `application.yaml`
>   (`hapi.fhir.implementationguides`), so it loads at boot.

## Deployment — Option D: official image + registry via proxy

We run the **official matchbox image unmodified**. Nothing is baked into the
image; there is no wrapper.

- [`application.yaml`](application.yaml) — shared base config (compose + k8s),
  **transform-only**: no IGs, boots lean (~2 GB).
- [`ig-validation.yaml`](ig-validation.yaml) — **k8s only**, layered on top via
  `spring.config.additional-location`. Loads `ch.fhir.ig.ch-etoc#3.0.1` (11
  packages, ~290 MB) so matchbox can `$validate` against `ch-etoc-document`. On
  first boot the closure is fetched from `packages.fhir.org` /
  `packages2.fhir.org` / `packages.simplifier.net` **through the corporate
  proxy** (those hosts must be allowed) and persisted on the PVC. Needs the 8Gi
  pod — a 3 GB container OOM-kills mid-install.
- [`load-maps.yaml`](load-maps.yaml) + [`load-maps.sh`](load-maps.sh) — **k8s
  Job** that `PUT`s every `maps/*.fml` to `StructureMap/<name>`
  (`text/fhir-mapping`, idempotent). It waits until the IG install has finished
  (`ch-etoc-document` searchable), since `/metadata` already answers while the
  first-boot install is still running. Runs as an ArgoCD PostSync hook.

Matchbox is **not on Docker Hub** — the official image is on Google Artifact
Registry (`europe-west6-docker.pkg.dev/ahdis-ch/ahdis/matchbox`, latest stable
`v4.1.14`). Mirror it into your registry as you do other official images and set:

- **k8s**: `matchbox.yaml` → `image: harbor-registry.io.usz.ch/prj-0011608-umzhc/matchbox:v4.1.14`;
  the `JAVA_TOOL_OPTIONS` proxy env there routes the IG fetch via the proxy.
- **compose**: `MATCHBOX_IMAGE` (default is the GAR ref). No proxy — needs
  direct internet access.

On k8s the proxy is passed as **JVM system properties** (the JVM ignores
`HTTP_PROXY` env by default), picked up automatically via `JAVA_TOOL_OPTIONS`:

```
-Dhttps.proxyHost=proxy -Dhttps.proxyPort=8080 \
-Dhttp.proxyHost=proxy  -Dhttp.proxyPort=8080 \
-Dhttp.nonProxyHosts=localhost|127.*|*.svc|*.cluster.local
```

**Heap:** the official entrypoint hard-codes `-Xmx12g`, which OOMs a normal pod.
Both the Deployment `command:` and the compose `entrypoint:` re-declare the
upstream command with `-XX:MaxRAMPercentage=75.0` instead — a config override,
no rebuild.

**Terminology:** `txServer: n/a` (pinned in `application.yaml`) — matchbox makes
**no `tx.fhir.org` call**. The only egress is the package fetch at boot.

### Database (embedded H2) and persistence

Matchbox is a HAPI JPA server, so a datasource always exists — but it's the
built-in **file-based H2** (`jdbc:h2:file:./database/h2` → `/database`); **no
external DB is required**.

- **Ephemeral** (no volume at `/database`): matchbox re-fetches the IGs (via the
  proxy) on every restart, and a POSTed StructureMap is lost. Simplest.
- **Persistent** (recommended): mount a volume at `/database` so installed
  packages **and** your POSTed map survive restarts.
  - **k8s**: the `matchbox-database` **PersistentVolumeClaim** (`ReadWriteOnce`, 10Gi)
    is mounted at `/database`; `securityContext.fsGroup: 1000` makes it writable
    by the image's `matchbox` user (uid 1000). Because file H2 is single-writer,
    keep **`replicas: 1`** and `strategy: Recreate`. Delete the PVC + mount to go
    ephemeral.
  - **compose**: the named volume `matchbox-db` is mounted at `/database`
    (`docker compose down -v` clears it).

## Air-gapped alternative — Option B (baking / internal mirror)

If the proxy **cannot** reach `packages.fhir.org`, don't rely on the boot fetch.
[`fetch-packages.sh`](fetch-packages.sh) resolves the full transitive package
closure from one root (`ch.fhir.ig.ch-umzh-connect#1.0.0-ballot`) — it handles
wildcard versions and skips the FHIR-core packages matchbox already provides —
producing the exact set of `.tgz` files. Then either:

- publish those tarballs to an **internal mirror** and give each
  `implementationguides` entry a `url:` (e.g. `url: https://mirror.internal/…tgz`
  or `url: file:/packages/…tgz`), or
- bake them into a wrapper image ([`Dockerfile`](Dockerfile) is a starting point;
  note matchbox loads via `url:`, **not** the `~/.fhir/packages` filesystem
  cache — a plain cache bake is ignored).

These artifacts are **not used by Option D** and are kept only for this path.

## Developing & testing the map

- **Map source:** [`maps/ServiceRequestBundleToChEtoc.fml`](maps/ServiceRequestBundleToChEtoc.fml)
  (FHIR Mapping Language; canonical = the workflow's `ETOC_STRUCTUREMAP_URL`).
  Currently a **running skeleton** (Bundle→Bundle passing ServiceRequest + Patient
  through) with `TODO`s for the CH eToC document/profile specifics.
- **Sample input:** drop the real searchset Bundle at
  [`examples/input-servicerequest-bundle.json`](examples/README.md) — the exact
  `getServiceRequest` response shape.
- **Run the loop** against a running matchbox:
  ```bash
  matchbox/test-transform.sh          # compiles+loads the .fml, runs $transform, prints result
  # MATCHBOX_URL overrides the base (default http://localhost:9088/matchboxv3/fhir)
  ```
  Needs `onlyOneEngine: true` (set) so the POSTed map is picked up at runtime; a
  persistent `/database` keeps it loaded across restarts.
- **Deployment loading:** on k8s the `matchbox-load-maps` Job loads the map (see
  above); re-run it after changing the `.fml`
  (`kubectl -n matchbox delete job matchbox-load-maps && kubectl apply -k matchbox/`).

## Notes

- **Exposure.** In-cluster / on the compose network as `matchbox:8080`. On k8s
  [`ingress.yaml`](ingress.yaml) also exposes it at
  `https://matchbox.dev.umzhc.io.usz.ch/matchboxv3/fhir` (for Bruno testing) —
  **unauthenticated**; drop it from `kustomization.yaml` outside trusted networks.
- **Config lives at `/config`** (`application.yaml`, optional `fhir-settings.json`);
  the entrypoint loads it via `spring.config.additional-location`.
- The `/matchboxv3` context path is set in `application.yaml`; if you change it,
  update `matchboxTransformUrl` in
  `kestra/flows/referral-reception.yml.template` (the single place the URL is
  defined).
