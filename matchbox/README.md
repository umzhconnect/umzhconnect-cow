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
>   (It is held in the engine's memory only, so it is lost on restart and must
>   be loaded again — see below.)
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
  proxy** (those hosts must be allowed) and persisted in Postgres. With v4.1.21
  the closure (11 packages) installs and validates in a 1.5 GiB container; the
  pod requests 2Gi with a 3Gi limit. It takes ~110 MB in Postgres.
- [`db-config.yaml`](db-config.yaml) + [`db-secret.yaml`](db-secret.yaml) —
  **k8s only**: the `DB_*` env for the Postgres datasource in `application.yaml`
  (`matchbox-db-config` ConfigMap; password in the plaintext
  `matchbox-db-secret`). Compose passes the same variables from `.env`.
- [`load-maps.sh`](load-maps.sh) — `PUT`s every `maps/*.fml` to
  `StructureMap/<name>` (`text/fhir-mapping`, idempotent), once
  `ch-etoc-document` is searchable (`/metadata` already answers while the
  first-boot IG install is still running). On k8s it runs as the **`load-maps`
  sidecar** of the matchbox pod in watch mode (`WATCH_INTERVAL=30`): it reloads
  a map whenever matchbox has lost it (every restart, see below) or its `.fml`
  changed in the `matchbox-maps` ConfigMap, and the sidecar is Ready only while
  all maps are loaded — so the pod takes traffic only once `$transform` works.

Matchbox is **not on Docker Hub** — the official image is on Google Artifact
Registry (`europe-west6-docker.pkg.dev/ahdis-ch/ahdis/matchbox`, pinned here to
`v4.1.21`). Mirror it into your registry as you do other official images and set:

- **k8s**: `matchbox.yaml` → `image: harbor-registry.io.usz.ch/prj-0011608-umzhc/matchbox:v4.1.21`;
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

**TLS inspection:** the USZ proxy re-signs HTTPS with *USZ Root CA 2*, which the
JVM doesn't trust (symptom: `HAPI-1301: Unable to locate package`). A
`truststore` initContainer (same image, its own `keytool`) copies the image's
default `cacerts`, imports [`truststore/usz-root-ca.crt`](truststore/usz-root-ca.crt)
(public cert, copied from `umzhconnect-auth`), and the JVM uses it via
`-Djavax.net.ssl.trustStore` in `JAVA_TOOL_OPTIONS`.

**Heap / JVM:** since 4.1.18 the image sizes the heap from the container limit
via `JDK_JAVA_OPTIONS` (`-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError
-XX:+UseStringDeduplication`). Both the Deployment `command:` and the compose
`entrypoint:` re-declare the upstream command only to also load
`ig-validation.yaml` (compose also forces SSRF protection on); `java` still reads
`JDK_JAVA_OPTIONS`. k8s raises the heap to `-XX:MaxRAMPercentage=75.0`, which
wins because it comes later on the command line.

**Terminology:** `txServer: n/a` (pinned in `application.yaml`) — matchbox makes
**no `tx.fhir.org` call**. The only egress is the package fetch at boot.

### Database and persistence

Matchbox is a HAPI JPA server: installed IG packages live in its database, so a
restart skips the IG download. StructureMaps loaded at runtime (`POST`/`PUT
text/fhir-mapping`) do **not**: the engine keeps them in memory only, so they are
lost on every restart. On k8s the `load-maps` sidecar puts them back
automatically; with compose, re-run `matchbox/test-transform.sh`.

Both compose and k8s use the **managed PostgreSQL** — the same external server
as HAPI and Kestra, with matchbox's **own database**. Create it (owned by
`DB_USERNAME`) before matchbox first starts; matchbox creates its schema on
first boot. The datasource in [`application.yaml`](application.yaml) replaces
matchbox's built-in H2 and has **no fallback**: `DB_HOST`, `DB_PORT`, `DB_NAME`,
`DB_USERNAME` and `DB_PASSWORD` must all be set, or matchbox fails to start.
Driver and Hibernate dialect are fixed literals (`org.postgresql.Driver`,
`HapiFhirPostgresDialect`, as in matchbox's `with-postgres` example) — keep the
dialect a literal: matchbox reads `spring.jpa.properties.*` without resolving
`${…}` placeholders.

- **compose:** the matchbox service passes `DB_*` from `.env`, with
  `DB_NAME` ← `MATCHBOX_DB_NAME` (default `matchbox`). For a Postgres on the
  Docker host it maps `host.docker.internal` (`extra_hosts`), like HAPI and
  Kestra.
- **k8s:** the pod gets them via `envFrom`:
  - [`db-config.yaml`](db-config.yaml) → `matchbox-db-config` ConfigMap:
    `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`;
  - [`db-secret.yaml`](db-secret.yaml) → `matchbox-db-secret` Secret:
    `DB_PASSWORD`, as **plaintext** `stringData` for the dev cluster. For a real
    deployment deliver it as a SealedSecret or out of band instead of committing
    it.

  The pod is stateless (no PVC). Keep **`replicas: 1`** and `strategy:
  Recreate`: two pods starting together would install the IG closure into the
  same database at once.

## Without the proxy (not implemented)

If the proxy can't reach the package registry — or to turn SSRF protection back
on (it must be off only because the proxy has a private IP) — matchbox would
have to load the IG closure from an **internal mirror** instead: publish the
`.tgz` files of all 11 packages there and point the `implementationguides`
entries at them. Note matchbox installs packages into its database; it does
**not** read the `~/.fhir/packages` filesystem cache, so copying packages into
the image is not enough.

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
  Needs `onlyOneEngine: true` (set) so the POSTed map is picked up at runtime;
  it is lost when matchbox restarts, so re-run the script then.
- **Deployment loading:** on k8s the `load-maps` sidecar loads the map (see
  above). After changing the `.fml`, apply/sync the kustomization: the sidecar
  sees the updated ConfigMap within about a minute (kubelet sync) and reloads it.
  Follow it with `kubectl -n matchbox logs deploy/matchbox -c load-maps -f`.

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
