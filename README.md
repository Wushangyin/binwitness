# binwitness

**English** · [简体中文](https://github.com/Wushangyin/binwitness/blob/main/README.zh-CN.md)

Software composition analysis for **what was actually delivered**: jars, wars, `docker save` images, zip
bundles and front-end builds, nested to any depth. Every component in the result carries the evidence it
was identified by, so each line of a report can be defended. binwitness also checks another scanner's
findings against public advisory data and classifies each disagreement.

```
$ binwitness scan release.zip -o out
walked 1 input(s): 5 distinct jars, 0 npm package entries, 0 distinct scripts
identified jars: 5 of 5
vulnerabilities: 133 distinct across 22 components
components   34  (maven 34; exact 5, content 0, declared 29)
jars         5 distinct: third-party 5, first-party 0, unidentified 0
vulns        133 distinct: critical 12, high 73, medium 46, low 2; known exploited 2
licenses     permissive 34
```

`release.zip` here holds five jars downloaded from Maven Central: log4j-core 2.14.1, jackson-databind 2.9.10,
commons-collections 3.2.1, mybatis 3.4.6 and netty-all 4.1.54.Final. The scan finds 34 components in them:
the 27 modules bundled in netty-all, plus ognl and javassist, which are shaded into mybatis. No advisory is
filed against `netty-all` itself; its modules carry 71. (Counts are from October 2026 data; they grow as
advisories are published.)

## Why another SCA tool

Trivy, Syft/Grype and OSV-Scanner identify jars and report vulnerabilities well. binwitness is built for
the reviewer who receives a delivery from someone else and has to sign off on the result:

- **Evidence, not guesses.** A component is identified because the file is byte-identical to a published
  artifact (`exact`), because every entry in it matches a published artifact entry by entry (`content`), or
  because the artifact declares its own coordinates (`declared`). File names are never turned into
  coordinates. Anything else is listed as unidentified, with the hints it carries.
- **Rebuilt jars are told apart from modified ones.** Fat-jar builds often re-zip their dependencies:
  directories dropped, manifest rewritten, timestamps changed. The file hash no longer matches, but the
  code is the same. binwitness reads the central directory of the published jar (a ranged request for its
  last few kilobytes) and compares every entry's CRC-32 and size. If only the manifest, the jar index or
  signatures differ, the jar is `repackaged`. If classes or resources differ, it is `differs`, and the
  changed, added and removed entries are listed. A jar packed inside another jar that is itself identical
  to its release is `inside-published`. Upstream put it there.
- **Bundled code is unpacked.** Fat jars (`BOOT-INF/lib`, `WEB-INF/lib`), shaded jars (embedded
  `pom.properties`) and all-in-one artifacts such as `netty-all` are expanded into their modules.
  Advisories are filed against the modules, so scanning `netty-all` by its own name misses them.
- **Other scanners' findings can be checked.** `binwitness crosscheck` takes another tool's result and,
  for every finding binwitness did not reproduce, looks up the advisory in GitHub's reviewed database. The
  finding is then classified as a real miss, attributed to another module of the same project, attributed
  to a different package, out of the affected version range, or recorded upstream without any package.
  Tools that match by product name (CPE) attach an advisory to every module of a product. This command
  shows how much of a report is noise of that kind.
- **Results state their data age.** Every response is cached with its fetch time, and the result records
  the oldest and newest data used from each source. `--offline` replays a scan from the cache on a
  machine without internet access.
- **Online, local, or both.** Advisory databases and Maven Central's hash index can be kept on disk and
  updated incrementally, so that scans identify jars and match advisories without sending anything.
  How much to keep is up to you; see [Local datasets](#local-datasets).
- **No dependencies.** binwitness uses only the Python standard library (3.10+).

## Install

```
pipx install binwitness
# or the latest commit
pipx install git+https://github.com/Wushangyin/binwitness
# or, from a checkout
pip install .
```

To open rar and 7z archives, `unrar`, `7z` or `bsdtar` must be on `PATH`, or passed with `--unpacker`.

## Scanning

```
binwitness scan INPUT... -o OUTDIR [options]
```

| Option | Purpose |
|---|---|
| `--first-party-group com.acme` | Maven groupId prefix of your own code. Repeatable. Not looked up, listed separately. |
| `--first-party-jar acme-` | jar file-name prefix of your own code. Repeatable. |
| `--first-party-npm @acme/` | npm name prefix of your own packages. Repeatable. |
| `--exclude GLOB` | skip locations, e.g. `*!/<registry/unrelated:*>` for one image of a multi-image tarball |
| `--class-search` | identify rebuilt jars that carry no coordinates (see below). Sends one class name per such jar to Maven Central |
| `--no-js` | do not look up vendored JavaScript files |
| `--fail-on high` | exit with status 3 if anything at or above that severity is found (for CI) |
| `--lookup auto\|local\|online` | where lookups are answered; see [Local datasets](#local-datasets). Default `auto` |
| `--maven-mirror URL` | fetch Maven Central files (checksums, POMs, jar directories) from a mirror of Maven Central, for machines far from it. Hash search and deps.dev still go to their own hosts. The mirror must serve Central's files unchanged and honour `Range`, or whole jars are downloaded. The result names the mirror (`options.mirrors`, `data_sources.online`) |
| `--offline` / `--max-age H` | no network: local datasets and the response cache only / refetch online vulnerability data older than H hours (default 12) |

What is examined:

| Found in the delivery | How it is identified |
|---|---|
| any `.jar` (top level, nested in fat jars, wars, zips, tars, images) | SHA-1 lookup in the local hash index when installed, on deps.dev, then on Maven Central search. Otherwise the jar's own `META-INF/maven/**/pom.properties`, compared with the file published under those coordinates: a matching published checksum makes the identification `exact`, matching entries make it `content`. |
| a jar with several `pom.properties`, none named after the file (renamed, and shading other libraries) | each declared artifact is compared with the jar entry by entry, the one named in the manifest first; the one whose published entries all match is the jar (`content`), the others are contained in it |
| renamed or re-zipped copies of a jar identified in the same delivery | every entry but the manifest, index and signatures has the CRC-32 and size of the identified jar: `content`, with no request. A copy whose entries match jars identified as different components (releases that changed only the version) stays unidentified and lists them in `same_content_as` |
| jars with none of the above (Gradle builds, renamed and re-zipped), with `--class-search` | a class from the jar's main package is looked up on Maven Central search, narrowed to the version the manifest or file name suggests. A candidate is accepted only if its published entries match the jar's (`content`); the hint itself is never trusted. |
| shaded jars | extra `pom.properties` inside the jar become components contained in the jar (`contained_in`). So does a jar's only `pom.properties` when the jar's name does not mention it and either most of that artifact's published entries are missing (guice carries only cglib's) or the jar holds more entries of its own than the artifact has (a driver that bundles a compression library whole) |
| `netty-all` style artifacts | the module list in `META-INF/io.netty.versions.properties` |
| `package-lock.json` (v1-v3), `yarn.lock` (classic and berry), `pnpm-lock.yaml` | listed packages, with dev/runtime scope where the lockfile records it |
| `node_modules/**/package.json` | installed packages |
| vendored `.js` files outside `node_modules` | byte-identical match with a file of an npm release (jsDelivr). A banner comment that names a release without a matching file gives a `declared` identification. |

Container images: layers are applied in order, whiteouts included, so only files present in the final
image are examined. Jars belonging to a JDK/JRE installation are skipped and counted.

The same file is sometimes published under several coordinates: a project that moved its groupId
(`com.oracle.ojdbc` and `com.oracle.database.jdbc`), a copy republished by someone else, a release that
did not change a jar. The component is named by the coordinates in the jar's own `pom.properties` when
they are among them, otherwise by one that matches the file name. The rest are listed with the file
(`also_published_as`), and advisories filed under any of them count for the component, marked with the
coordinate they name.

### Output

| File | Content |
|---|---|
| `binwitness.json` | everything: components with evidence, locations, file hashes, published-artifact comparison, other coordinates of the same file, licenses, vulnerabilities; first-party and unidentified files; warnings; data sources with fetch times |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM with vulnerabilities, identity evidence and occurrences |
| `components.csv`, `vulnerabilities.csv` | the same in spreadsheet form |

Severity comes from the advisory where it states one (GitHub's rating). Otherwise it is computed from the
CVSS v3 vector. Records from the OpenSSF malicious-packages feed count as critical. Findings are merged by
CVE, so a GHSA and its CVE are counted once. Each finding lists the fixed versions per component and the
date CISA added it to the Known Exploited Vulnerabilities catalog, if it is there.

Licenses are taken from the artifact first: the embedded `pom.xml`, the `Bundle-License` header or a
LICENSE file, read in full so that exceptions appended after a GPL text are seen. When the artifact has
none, binwitness uses the registry (deps.dev) and then the published POM, including its parents. Licenses
are grouped into families: `permissive`, `weak-copyleft`, `copyleft-with-exception`, `strong-copyleft`,
`source-available`, `unknown`.

## Local datasets

Without any setup, binwitness asks online services and caches every answer, so the cache holds exactly
what your scans needed. You can also keep whole datasets on disk:

```
binwitness db sync osv-maven kev      # some datasets
binwitness db sync all                # all of them
binwitness db sync                    # update the installed ones
binwitness db status                  # what is installed, how old, how large, what the next sync does
binwitness db remove osv-npm
```

| Dataset | Content | Size |
|---|---|---|
| `osv-maven` | OSV advisories for Maven packages | 10 MB download, 13 MB on disk |
| `osv-npm` | OSV advisories for npm packages, including malicious-package reports | 210 MB download, 250 MB on disk |
| `kev` | CISA Known Exploited Vulnerabilities catalog | 2 MB |
| `maven-hashes` | SHA-1 of every jar on Maven Central ([Trivy java-db](https://github.com/aquasecurity/trivy-java-db), then the additions to Central's own index) | 1 GB download, 1.5 GB on disk; then 10-50 MB every week or two |

Groups: `vulns` (both OSV datasets and `kev`), `java` (`osv-maven`, `kev`, `maven-hashes`), `all`.
Datasets live in `~/.cache/binwitness/datasets` (`--db-dir`, or `$BINWITNESS_DB`).

Updates are incremental where the publisher allows it. OSV keeps a list of records by modification time,
so an update fetches only the records changed since the previous one. If more than 5,000 records have
changed, or the last full download is a month old, the archive is downloaded again instead; that also
drops records deleted upstream. The KEV catalog is small and fetched whole.

The hash index starts from Trivy's java-db, which is rebuilt every day as one 1 GB file with no incremental
form. After that, each sync applies the additions that Maven Central publishes to its own index every week
or two (10-50 MB each; Central lists several months of them), so the copy stays current without the 1 GB.
The base itself is downloaded again every 180 days (`--hashes-every DAYS`), or with `--full`. If Central
restarts its index, or the copy is older than the additions it still lists, the sync stops and asks for
`--full` instead of starting a 1 GB download on its own.

Maven Central limits how much of its index one address may download. A sync therefore looks for new
additions at most once a week, and saves its progress after each one it applies. If Central answers
that the limit is reached (HTTP 429), the sync stops at once and says when to try again: retrying earlier
only extends the block.

A dropped connection resumes where it stopped, and a sync that gives up resumes on the next run. If a
sync fails, the copy already installed is kept. Only one `db sync` or `db remove` runs on a directory at a
time; a second one is refused rather than left waiting behind a download that can take an hour on a slow
line.

`scan --lookup` chooses how the datasets are used:

| Mode | Behaviour |
|---|---|
| `auto` (default) | installed datasets first; online services for the rest and for what the datasets do not cover. Without datasets, this is the same as `online` |
| `local` | no network at all: installed datasets, then the response cache. Same as `--offline` |
| `online` | ignore installed datasets. With `--offline`, replays an earlier online scan from the cache exactly |

The datasets cover jar identification by hash, vulnerability matching and the KEV flag. Some lookups
still need the network or a cached answer from an earlier online scan: the checksum Maven Central
publishes for a jar the hash index does not list, licenses that the artifact itself does not state, the
entry-by-entry comparison of rebuilt jars with their published originals, `--class-search`, and vendored
JavaScript files. In `local` mode, what is neither in a dataset nor in the cache is left out and counted
in a warning; a jar that stays unidentified for that reason says so, since an online scan may identify it.

The hash index records one coordinate per file, where deps.dev lists all of them, and deps.dev leaves out
classifier jars (`json-lib-2.4-jdk15.jar`), which the index has. When a jar's `pom.properties` names
coordinates the index does not give, or the indexed coordinates do not match the file name, binwitness
asks deps.dev (or the cache) as well. For a jar that declares nothing, the two sources can still name
different coordinates of the same file, so a `local` and an `online` scan may differ in a component's
name; with `auto`, the index answers first, as in `local`.

The result records which datasets answered and how current they were (`data_sources.local`). A dataset
last synced more than seven days ago produces a warning.

Each dataset is downloaded by your machine directly from its publisher, under the publisher's terms: OSV
from Google's public bucket (each record carries the license of the database it comes from), the hash
index from Aqua Security's `trivy-java-db` image on ghcr.io and from Maven Central's index, the KEV catalog
from CISA.

## Cross-checking another scanner

```
binwitness crosscheck out/binwitness.json other-tool.csv -o crosscheck.json
```

The other tool's result can be CycloneDX JSON with a `vulnerabilities` section, or a CSV with the
columns `component,version,vulnerability`. In the CSV, `component` is `group:artifact`, `npm:name` or a
purl. A blank vulnerability means the tool identified the component and found nothing.

Only components that both tools identified at the same version are compared. Identification differences
are listed separately. Each finding binwitness did not reproduce receives one class:

| Class | Meaning |
|---|---|
| `confirmed` | GitHub lists this package and version as affected |
| `bundled-module` | the advisory names a module bundled inside this artifact (netty-all, shaded jars) |
| `version-not-affected` | right package, but this version is outside the affected range |
| `same-project-other-module` | the advisory names a sibling module (`netty-codec-http` reported on `netty-handler`) |
| `other-package` | the advisory names a different package or ecosystem |
| `unattributed` | the upstream advisory names no package (GitHub "unreviewed"); needs a human |
| `no-github-record` / `tool-specific-id` | nothing public to check against |

A GitHub token raises the API limit from 60 to 5,000 lookups per hour. binwitness reads it from
`GITHUB_TOKEN`, from `GH_TOKEN` or from `gh auth token`.

## What leaves your machine

binwitness sends the following to public services:

- SHA-1 hashes of jars, and SHA-256 hashes of JavaScript files
- component coordinates and versions
- CVE identifiers
- with `--class-search` only: one fully qualified class name for each jar that nothing else identified.
  Classes under `--first-party-group` prefixes are never sent. An unidentified jar may be private code,
  so its class name can reveal a package name. Leave the option off when that matters.

It never uploads file contents. First-party jars are not looked up. With `--maven-mirror`, requests for
Maven Central files go to the mirror instead, so its operator sees which coordinates you checked. With `--lookup local` nothing is
sent at all. `binwitness db sync` only downloads public datasets and sends nothing about your files. To
scan a machine with no internet access, copy the dataset directory and, optionally, the response cache
(`--cache-dir`, default `~/.cache/binwitness`) from a connected one.

| Service | Used for |
|---|---|
| [deps.dev](https://deps.dev) | jar hash to coordinates; licenses |
| [Maven Central](https://central.sonatype.com) | hash search fallback; published checksums; POM licenses |
| [OSV.dev](https://osv.dev) | vulnerabilities (GitHub Security Advisories and others) |
| [jsDelivr](https://www.jsdelivr.com) | JavaScript file hashes |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | known exploited flag |
| [OSV data bucket](https://google.github.io/osv.dev/data/) | `db sync` of the OSV datasets |
| [ghcr.io](https://github.com/aquasecurity/trivy-java-db) | `db sync` of the Maven Central hash index |
| [Maven Central index](https://repo1.maven.org/maven2/.index/) | `db sync`: weekly additions to the hash index |
| [GitHub advisories](https://github.com/advisories) | `crosscheck` only |

## Limitations

These limits are deliberate, so read them before relying on a result:

- **Local matching uses binwitness's version ordering.** Advisory ranges in a local dataset are
  evaluated by binwitness's implementation of Maven and semver ordering, the online API by OSV's own.
  They agree on ordinary versions; unusual version strings can compare differently.
- **Advisory coverage is that of OSV.** An advisory that names no package (GitHub "unreviewed",
  NVD-only CPE records) cannot be matched to a component. Vendor-private and national vulnerability
  databases are not consulted. Treat counts as a lower bound. `crosscheck` against a commercial tool's
  output is the practical way to see what such a database adds.
- **Identification needs a published artifact or a declaration.** A private build, a fork or a relocated
  copy of a library with no `pom.properties` stays unidentified, unless the same delivery also carries a
  copy that was identified (or `--class-search` finds it). Classes shaded without their
  `pom.properties` are not recognised; binwitness does no bytecode or source fingerprinting. Content
  matching compares CRC-32 values. It catches rebuilds and ordinary edits, not a deliberately forged
  collision. Jars that hold only a manifest, a license and a notice (Spring Boot starters) look alike
  across artifacts; they are never matched by content and are reported as holding no code. Classifier jars (`-linux-x86_64`) are compared only with the main artifact.
- **Front-end bundles are opaque.** Code that webpack or rollup merged into chunks cannot be matched by
  hash. Ship the lockfile, or the `node_modules` the build used, alongside the bundle. Banner comments
  give only partial coverage.
- **Ecosystems: Java (Maven) and JavaScript (npm).** OS packages, Python, Go, .NET and native libraries
  are out of scope; use Trivy or Syft for an image's OS layer. JDK/JRE runtime jars are skipped.
- **Unusual licenses need a human.** Non-standard licenses and contradictory declarations end up as
  `unknown`. Dual licenses listed without an SPDX expression are read as alternatives.
- **Scanning speed depends on the network.** A cold-cache scan is almost entirely waiting for lookups: a
  war with 190 jars takes about three minutes, a delivery with a thousand jars roughly a quarter of an hour.
  A request that stalls, name lookup included, is abandoned after 30 seconds and retried. A rerun from cache takes seconds, and
  common libraries looked up for one delivery are already cached for the next.
- **Online services can be down or rate-limited.** Failed lookups are retried with backoff for about a
  minute and then recorded as warnings, so a scan does not fail outright.

## Development

```
pip install -e ".[test]"
pytest
```

Tests build their own archives and answer network calls from scripted responses; they never touch the
internet.

## License

Apache-2.0
