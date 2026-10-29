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
components   34  (maven 34; exact 5, declared 29)
jars         5 distinct: third-party 5
vulns        133 distinct: critical 12, high 73, medium 46, low 2, known exploited 2
  critical CVE-2021-44228       org.apache.logging.log4j:log4j-core 2.14.1, fixed in 2.15.0 KEV
  critical CVE-2021-45046       org.apache.logging.log4j:log4j-core 2.14.1, fixed in 2.16.0 KEV
  critical CVE-2015-7501        commons-collections:commons-collections 3.2.1, fixed in 3.2.2
  critical CVE-2019-16942       com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.1
  critical CVE-2019-16943       com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.1
  critical CVE-2019-17531       com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.1
  critical CVE-2019-20330       com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.2
  critical CVE-2020-8840        com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.3
  critical CVE-2020-9546        com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.4
  critical CVE-2020-9547        com.fasterxml.jackson.core:jackson-databind 2.9.10, fixed in 2.9.10.4
  ... 75 more (vulnerabilities.csv)
licenses     permissive 34
```

`release.zip` here holds five jars downloaded from Maven Central: log4j-core 2.14.1, jackson-databind 2.9.10,
commons-collections 3.2.1, mybatis 3.4.6 and netty-all 4.1.54.Final. The scan finds 34 components in them:
the 27 modules bundled in netty-all, plus ognl and javassist, which are shaded into mybatis. No advisory is
filed against `netty-all` itself; its modules carry 71. The summary names the worst findings first
(malicious, known exploited, critical, high) with the release that fixes each; `vulnerabilities.csv` has
all of them. (Counts are from October 2026 data; they grow as advisories are published.)

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
  last few kilobytes) and compares every entry's CRC-32 and size. If only the manifest, the jar index,
  signatures or the Maven build metadata under `META-INF/maven` differ, the jar is `repackaged`. If classes or resources differ, it is `differs`, and the
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
A Java EE resource adapter (`.rar`) is a zip and needs none of them.

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
| `--class-search` | identify rebuilt jars that carry no coordinates (see below). Sends one class name per such jar to Maven Central, and asks for the coordinates its name suggests |
| `--maven-repo URL` | another Maven repository that publishes releases Maven Central does not have: milestones, a vendor's or your company's own. Checked after Central, in the order given, for checksums, jar directories and POM licenses. Repeatable |
| `--no-js` / `--no-licenses` / `--no-vulns` | do not look up vendored JavaScript files / licenses / vulnerabilities |
| `--fail-on high` | exit with status 3 if anything at or above that severity is found, and with 4 if nothing is but the scan could not check everything (failed or offline lookups) or found nothing to check (for CI) |
| `--unpacker PROGRAM` | the rar/7z extractor to use (`unrar`, `7z` or `bsdtar`); by default the first one on `PATH` |
| `--lookup auto\|local\|online` | where lookups are answered; see [Local datasets](#local-datasets). Default `auto` |
| `--maven-mirror URL` | fetch Maven Central files (checksums, POMs, jar directories) from a mirror of Maven Central, for machines far from it. Hash search and deps.dev still go to their own hosts. The mirror must serve Central's files unchanged and honour `Range`, or whole jars are downloaded. The result names the mirror (`options.mirrors`, `data_sources.online`) |
| `--offline` / `--max-age H` | no network: local datasets and the response cache only / refetch online vulnerability data older than H hours (default 12) |
| `--workers N` | parallel lookups (default 16). Maven Central search gets at most two at a time |
| `--cache-dir DIR` / `--db-dir DIR` | response cache (default `~/.cache/binwitness`, or `$BINWITNESS_CACHE`) / local datasets (see [Local datasets](#local-datasets)) |

What is examined:

| Found in the delivery | How it is identified |
|---|---|
| any `.jar`, and plugins and libraries packed the same way (`.hpi`, `.jpi`, `.aar`, `.nar`, `.kar`, resource adapter `.rar`), at top level or nested in fat jars, wars, ears, zips, tars, images | SHA-1 lookup in the local hash index when installed, on deps.dev, then on Maven Central search. Otherwise the jar's own `META-INF/maven/**/pom.properties`, compared with the file published under those coordinates on Maven Central, then on the `--maven-repo` repositories: a matching published checksum makes the identification `exact`, matching entries make it `content`. |
| a jar with several `pom.properties`, none named after the file (renamed, and shading other libraries) | each declared artifact is compared with the jar entry by entry, the one named in the manifest first; the one whose published entries all match is the jar (`content`), the others are contained in it |
| renamed or re-zipped copies of a jar identified in the same delivery | every entry but the manifest, index, signatures and Maven build metadata has the CRC-32 and size of the identified jar: `content`, with no request. A copy whose entries match jars identified as different components (releases that changed only the version) stays unidentified and lists them in `same_content_as` |
| jars with none of the above (Gradle builds, renamed and re-zipped), with `--class-search` | candidates come from three places, tried in turn: a class from the jar's main package looked up on Maven Central search, narrowed to the version the manifest or file name suggests; the artifact names the file name and manifest suggest, under the groupIds of that package and of identified jars of the same family (`spring-jcl` beside `spring-core`); and, with `--maven-repo`, the artifacts Central search lists for the class, at the suggested version. A candidate is accepted only if its published entries match the jar's (`content`); the hints themselves are never trusted. |
| shaded jars | extra `pom.properties` inside the jar become components contained in the jar (`contained_in`). So does a jar's only `pom.properties` when the jar's name does not mention it and either most of that artifact's published entries are missing (guice carries only cglib's) or the jar holds more entries of its own than the artifact has (a driver that bundles a compression library whole) |
| `netty-all` style artifacts | the module list in `META-INF/io.netty.versions.properties` |
| `package-lock.json` (v1-v3), `yarn.lock` (classic and berry), `pnpm-lock.yaml` | listed packages, with dev/runtime scope where the lockfile records it. An alias (`name@npm:other@1.0.0`) is named by the package it installs. Inside `node_modules`, only npm's own `node_modules/.package-lock.json` counts: the lockfiles that packages publish were never installed |
| `node_modules/**/package.json` | installed packages |
| vendored `.js` files outside `node_modules` | byte-identical match with a file of an npm release (jsDelivr). A banner comment that names a release without a matching file gives a `declared` identification. |
| a file whose extension says nothing (`app.bin`, `plugin.dat`) | its first bytes: a zip with classes of its own is examined as a jar; other zips, tars (also gzip or xz compressed), rar and 7z archives are opened |

Container images: `docker save` tarballs and OCI image layouts, packed as a tar or unpacked into a
directory; each platform of a multi-platform image is examined on its own. Layers are applied in order,
whiteouts included, so only files present in the final image are examined. Jars belonging to a JDK/JRE
installation (a directory with a `release` file beside `bin/java` or `lib/modules`) are skipped and counted.

Directories are walked with their symbolic links followed; a link back into a directory already walked is
not followed again. Entries larger than 16 MB are read from a temporary file rather than kept in memory,
and one that expands more than a hundredfold is skipped as a decompression bomb. Whatever is skipped (a
broken link, an archive that cannot be read, a bomb, a link inside an archive) is listed in the warnings.

The same file is sometimes published under several coordinates: a project that moved its groupId
(`com.oracle.ojdbc` and `com.oracle.database.jdbc`), a copy republished by someone else, a release that
did not change a jar. The component is named by the coordinates in the jar's own `pom.properties` when
they are among them, otherwise by one that matches the file name. A jar whose contents match several copies
of the same release is named by the one whose packaging differs least from it: the original, not the
`commons-collections` that `org.lucee` republishes. The rest are listed with the file
(`also_published_as`), and advisories filed under any of them count for the component, marked with the
coordinate they name.

### Output

| File | Content |
|---|---|
| `binwitness.json` | everything: components with evidence, locations, file hashes, published-artifact comparison, other coordinates of the same file, licenses, vulnerabilities; first-party and unidentified files; warnings; data sources with fetch times |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM with vulnerabilities, identity evidence and occurrences. A component found in several different files has one entry per file, each with its hashes; first-party and unidentified jars are `file` components with their hashes. Licenses with an SPDX id are given as `license.id`. `metadata.component` describes what was scanned |
| `components.csv`, `vulnerabilities.csv` | the same in spreadsheet form, UTF-8 with a byte order mark so that Excel reads non-ASCII paths correctly |

When a lookup fails (a service is down, or `--offline` finds nothing cached), the summary has an
`INCOMPLETE` line saying what was not checked, `summary.incomplete` in `binwitness.json` counts it, and
each component whose vulnerabilities were not looked up has `vulnerabilities_checked: false`. No
vulnerabilities there means "not checked", not "none".

Severity comes from the advisory where it states one (GitHub's rating). Otherwise it is computed from the
CVSS v3 vector. Records from the OpenSSF malicious-packages feed count as critical. Findings are merged by
CVE, so a GHSA and its CVE are counted once. Each finding lists the fixed versions per component and the
date CISA added it to the Known Exploited Vulnerabilities catalog, if it is there.

Licenses are taken from the artifact first: the embedded `pom.xml`, the `Bundle-License` header or a
LICENSE file, read in full so that exceptions appended after a GPL text are seen. When the artifact has
none, binwitness uses the registry (deps.dev) and then the published POM, including its parents. Licenses
are grouped into families: `permissive`, `weak-copyleft`, `copyleft-with-exception`, `strong-copyleft`,
`source-available`, `unknown`. Names are given as SPDX ids, with the version the text states
(`The Apache Software License, Version 2.0` is `Apache-2.0`, `New BSD License` is `BSD-3-Clause`). A name
that does not say which version or variant, such as a bare `BSD`, is kept as it is. A GPL text that says
neither "only" nor "or later" keeps SPDX's older id (`GPL-2.0`, `GPL-2.0-with-classpath-exception`), which
claims no more than the text does.

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

GitHub's search by CVE finds only advisories that carry the CVE id, and a project's own advisory sometimes
lists it only as related (netty's for HTTP/2 Rapid Reset, CVE-2023-44487). For a Maven finding GitHub does
not attribute to the component, binwitness therefore also reads the OSV advisories of every module of its
groupId: one that affects this version and cites the CVE makes the finding `confirmed`, one for a sibling
module makes it `same-project-other-module`.

A GitHub token raises the API limit from 60 to 5,000 lookups per hour. binwitness reads it from
`GITHUB_TOKEN`, from `GH_TOKEN` or from `gh auth token`.

## What leaves your machine

binwitness sends the following to public services:

- SHA-1 hashes of jars, and SHA-256 hashes of JavaScript files
- component coordinates and versions
- CVE identifiers
- with `--class-search` only: one fully qualified class name for each jar that nothing else identified,
  and the coordinates its file name and manifest suggest. Classes under `--first-party-group` prefixes are never sent. An unidentified jar may be private code,
  so its class name can reveal a package name. Leave the option off when that matters.

It never uploads file contents. First-party jars are not looked up. With `--maven-mirror`, requests for
Maven Central files go to the mirror instead, so its operator sees which coordinates you checked. The
operators of `--maven-repo` repositories see the coordinates asked of them in the same way. With
`--lookup local` nothing is sent at all. `binwitness db sync` only downloads public datasets and sends nothing about your files. To
scan a machine with no internet access, copy the dataset directory and, optionally, the response cache
(`--cache-dir`, default `~/.cache/binwitness`) from a connected one.

| Service | Used for |
|---|---|
| [deps.dev](https://deps.dev) | jar hash to coordinates; licenses |
| [Maven Central](https://central.sonatype.com) | hash search fallback; published checksums; POM licenses; `--class-search`; the modules of a groupId for `crosscheck` |
| repositories given with `--maven-repo` | checksums, jar directories and POM licenses of releases Central does not have |
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
  copy that was identified (or `--class-search` finds it). A release that only another repository
  publishes (a milestone, a vendor's own build) needs `--maven-repo`. Each unidentified jar states why and
  shows what its manifest or file name suggests (`hint`), unverified. Classes shaded without their
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
  A connection not made within 10 seconds, or a request that stalls for 30, name lookup included, is
  abandoned and retried. Maven Central's search service, which `--class-search` relies on, holds some
  requests for up to a minute before it answers; binwitness sends it two at a time and asks again after
  8 seconds. A rerun from cache takes seconds, and common libraries looked up for one delivery are already
  cached for the next.
- **Online services can be down or rate-limited.** Failed lookups are retried with backoff for about a
  minute and then recorded as warnings, so a scan does not fail outright. The result is then marked
  `INCOMPLETE`, and `--fail-on` exits with status 4 rather than 0.

## Development

```
pip install -e ".[test]"
pytest
```

Tests build their own archives and answer network calls from scripted responses; they never touch the
internet.

## License

Apache-2.0
