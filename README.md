# binwitness

**English** · [简体中文](https://github.com/Wushangyin/binwitness/blob/main/README.zh-CN.md)

Software composition analysis for **what was actually delivered**: jars, wars, `docker save` images, zip
bundles and front-end builds, nested to any depth. Every component in the result carries the evidence it
was identified by, so each line of a report can be defended. For each vulnerable component it names the
nearest published release outside the package's advisories. CVEs that no advisory attributes to a package
are listed apart, as [candidates](#nvd-candidates) for review. binwitness also checks another scanner's
findings against public advisory data and classifies each disagreement, and an [MCP server](#mcp-server)
lets an AI assistant run scans and read their results.

```
$ binwitness scan release.zip -o out
walked 1 input(s): 5 distinct jars, 0 npm package entries, 0 distinct scripts
identified jars: 5 of 5
vulnerabilities: 133 distinct across 22 components
candidates: 2 NVD records not attributed to a package, for 22 components with a learned CPE
upgrade advice: upgrade 22
components   34  (maven 34; exact 5, declared 29)
jars         5 distinct: third-party 5
vulns        133 distinct: critical 12, high 73, medium 46, low 2, known exploited 2
  critical CVE-2021-44228       org.apache.logging.log4j:log4j-core 2.14.1, upgrade to 2.25.4 KEV
  critical CVE-2021-45046       org.apache.logging.log4j:log4j-core 2.14.1, upgrade to 2.25.4 KEV
  critical CVE-2015-7501        commons-collections:commons-collections 3.2.1, upgrade to 3.2.2
  critical CVE-2019-16942       com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  critical CVE-2019-16943       com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  critical CVE-2019-17531       com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  critical CVE-2019-20330       com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  critical CVE-2020-8840        com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  critical CVE-2020-9546        com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  critical CVE-2020-9547        com.fasterxml.jackson.core:jackson-databind 2.9.10, upgrade to 2.18.11
  ... 75 more, and medium 46, low 2 not listed here (vulnerabilities.csv)
upgrades     upgrade on the same line 22; 2 advisories name a fixed version that is not published
candidates   2 NVD records not attributed to a package in the local OSV data, not counted above; leads for manual review: high 1, medium 1, disputed 1 (candidates.csv)
             looked for in 22 components whose CPE could be learned; 12 without one were not checked; NVD has given no CPE yet to 74,887 records (local nvd of 2026-10-29, osv-maven of 2026-10-28, osv-npm of 2026-10-29)
             3 component pairs, flagged for review: none; 16 pairs left out: the record names another module; 2 CPE links refused: NVD's versions never meet OSV's
licenses     permissive 34
```

`release.zip` here holds five jars downloaded from Maven Central: log4j-core 2.14.1, jackson-databind 2.9.10,
commons-collections 3.2.1, mybatis 3.4.6 and netty-all 4.1.54.Final. The scan finds 34 components in them:
the 27 modules bundled in netty-all, plus ognl and javassist, which are shaded into mybatis. None of the
advisories filed against `netty-all` itself affects 4.1.54; its modules carry 71. The summary names the worst
findings first (malicious, known exploited, critical, high); `vulnerabilities.csv` has all of them. Each
comes with the nearest published release outside every advisory of its package: jackson-databind 2.18.11, not
the 2.9.10.1 that fixes the first of its findings, since dozens of later advisories cover 2.9.10.1 too (see
[Upgrade advice](#upgrade-advice)). The two candidates are NVD records that no advisory attributes to a
package; they need the local `nvd` dataset, and without it the summary says they were not checked (see [NVD
candidates](#nvd-candidates)). (Counts are from October 2026 data; they grow as advisories are published.)

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
- **Unattributed CVEs are leads, not findings.** Some CVEs are never attributed to a package: GitHub
  leaves them unreviewed, or has no record. NVD names them by product (CPE). binwitness learns which CPE
  stands for a package from the CVEs OSV does attribute to it, never from names, and lists NVD's other
  records for that CPE as [candidates](#nvd-candidates), kept to the module a record names. Before NVD
  has given a record a CPE, the record as the CNA published it is read the same way
  ([cvelist](#before-nvd-the-cnas-records)). Candidates are kept out of the findings and their counts.
- **Upgrade targets are checked, not copied.** An advisory's "fixed in" names the first fix of one
  flaw. binwitness reads every advisory of the package and the versions actually published, and proposes
  the nearest release outside all of them. A fixed version that an advisory names but nobody published
  is reported as such, never proposed.
- **Results state their data age.** Every response is cached with its fetch time, and the result records
  the oldest and newest data used from each source. `--offline` replays a scan from the cache on a
  machine without internet access.
- **Online, local, or both.** Advisory databases and Maven Central's hash index can be kept on disk and
  updated incrementally, so that scans identify jars and match advisories without sending anything.
  How much to keep is up to you; see [Local datasets](#local-datasets).
- **No dependencies.** binwitness uses only the Python standard library (3.10+). The optional MCP server
  needs the MCP SDK.

## Install

```
pipx install binwitness
# with the MCP server
pipx install "binwitness[mcp]"
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
| `--exclude GLOB` | skip locations, e.g. `*!/<registry/unrelated:*>` for one image of a multi-image tarball. A directory every file under which the pattern skips (`*/target/*`) is not walked at all |
| `--class-search` | identify rebuilt jars that carry no coordinates (see below). Sends one class name per such jar to Maven Central, and asks for the coordinates its name suggests |
| `--maven-repo URL` | another Maven repository that publishes releases Maven Central does not have: milestones, a vendor's or your company's own. Checked after Central, in the order given, for checksums, jar directories and POM licenses. Repeatable |
| `--no-js` / `--no-licenses` / `--no-vulns` | do not look up vendored JavaScript files / licenses / vulnerabilities |
| `--no-upgrades` | do not work out [upgrade advice](#upgrade-advice) (saves the advisory and version-list lookups of each vulnerable package) |
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
| any `.jar`, and plugins and libraries packed the same way (`.hpi`, `.jpi`, `.aar`, `.nar`, `.kar`, resource adapter `.rar`), at top level or nested in fat jars, wars, ears, zips, tars, images | SHA-1 lookup in the local hash index when installed; for a file it does not list, on deps.dev, then on Maven Central search. Otherwise the jar's own `META-INF/maven/**/pom.properties`, compared with the file published under those coordinates on Maven Central, then on the `--maven-repo` repositories: a matching published checksum makes the identification `exact`, matching entries make it `content`. |
| a jar with several `pom.properties`, none named after the file (renamed, and shading other libraries) | each declared artifact is compared with the jar entry by entry, the one named in the manifest first; the one whose published entries all match is the jar (`content`), the others are contained in it |
| renamed or re-zipped copies of a jar identified in the same delivery | every entry but the manifest, index, signatures and Maven build metadata has the CRC-32 and size of the identified jar: `content`, with no request. This also holds for a copy whose only `pom.properties` is not borne out by its file name and could not be compared with a published artifact (a library shaded into it, read offline), unless the identified jar is another release of the artifact it declares. A copy whose entries match jars identified as different components (releases that changed only the version) stays unidentified and lists them in `same_content_as` |
| jars with none of the above (Gradle builds, renamed and re-zipped), with `--class-search` | candidates come from three places, tried in turn: a class from the jar's main package looked up on Maven Central search, narrowed to the version the manifest or file name suggests; the artifact names the file name and manifest suggest, under the groupIds of that package and of identified jars of the same family (`spring-jcl` beside `spring-core`); and, with `--maven-repo`, the artifacts Central search lists for the class, at the suggested version. A candidate is accepted only if its published entries match the jar's (`content`); the hints themselves are never trusted. |
| shaded jars | extra `pom.properties` inside the jar become components contained in the jar (`contained_in`). So does a jar's only `pom.properties` when the jar's name does not mention it and either most of that artifact's published entries are missing (guice carries only cglib's) or the jar holds more entries of its own than the artifact has (a driver that bundles a compression library whole) |
| `netty-all` style artifacts | the module list in `META-INF/io.netty.versions.properties` |
| `package-lock.json` (v1-v3), `yarn.lock` (classic and berry), `pnpm-lock.yaml` | listed packages, with dev/runtime scope where the lockfile records it. An alias (`name@npm:other@1.0.0`) is named by the package it installs. Inside `node_modules`, only npm's own `node_modules/.package-lock.json` counts: the lockfiles that packages publish were never installed |
| `node_modules/**/package.json` | installed packages |
| vendored `.js` files outside `node_modules` | byte-identical match with a file of an npm release (jsDelivr). The hash index names one release even when many hold the same file, so the version is kept only when the releases before and after it hold a different file, or when a lockfile or `package.json` in the delivery declares a version whose release holds the file. Otherwise the file is listed in `scripts_without_version` with the releases found to hold it, and no component or vulnerability is made of it. A banner comment that names a release without a matching file gives a `declared` identification. Build configuration (`*.config.js`, `.eslintrc.js`) and plain sources under `src/`, `scripts/` or `tests/` (outside asset and library directories, with no license notice, UMD wrapper or minification) are the project's own and are not looked up (`project_scripts`). Of the files nothing matches, bundler output (webpack, Vite, Parcel chunks) is listed in `bundled_scripts`, the rest in `unmatched_scripts`. |
| a file whose extension says nothing (`app.bin`, `plugin.dat`) | its first bytes: a zip with classes of its own is examined as a jar; other zips, tars (also gzip or xz compressed), rar and 7z archives are opened |

Container images: `docker save` tarballs and OCI image layouts, packed as a tar or unpacked into a
directory; each platform of a multi-platform image is examined on its own. Layers are applied in order,
whiteouts included, so only files present in the final image are examined. Jars belonging to a JDK/JRE
installation (a directory with a `release` file beside `bin/java` or `lib/modules`) are skipped and counted.

Directories are walked with their symbolic links followed; a link back into a directory already walked is
not followed again. Entries larger than 16 MB are read from a temporary file rather than kept in memory,
and one that expands more than a hundredfold is skipped as a decompression bomb. Whatever is skipped (a
broken link, an archive that cannot be read, a bomb, a link inside an archive) is listed in the warnings.
Build caches are skipped and listed in `skipped_build_caches`: directories tagged with `CACHEDIR.TAG`
(Cargo's `target/`), `.next/cache`, `node_modules/.cache`, `.angular/cache`, `.parcel-cache` and the
like. Dependency files of ecosystems binwitness does not read (`requirements.txt`, `pyproject.toml`,
`go.mod`, `Cargo.toml`, `Gemfile`, `composer.json` and others) are named in a warning and in
`not_covered`, so that a result without their dependencies is not taken for a clean one.

The same file is sometimes published under several coordinates: a project that moved its groupId
(`com.oracle.ojdbc` and `com.oracle.database.jdbc`), a copy republished by someone else, a release that
did not change a jar. The component is named by the first of them in this order: the coordinates in the
jar's own `pom.properties`, one that matches the file name, one whose groupId the jar's packages are in,
the artifact with more releases in the hash index (the line that went on publishing; only with the index
installed), then alphabetical order. The hash index files each file under one coordinate only, often a
republication (commons-io in a NetBeans module, Bouncy Castle 1.38 under the old `bouncycastle` groupId),
and then lists no file under the original's version. The jar's `pom.properties` names the original in that
case, unless it names the indexed artifact itself with another version (`7.4.1` for `7.4.1.jre8`, a
snapshot). Failing that, the file name (`bcprov-jdk14-1.38.jar`) does, when the index knows that artifact,
lists no file for that version and numbers its releases the same way; of several groupIds that publish the
artifact, the one the packages are in is taken, then one with releases before and after that version, the
indexed one, the one with more releases. A jar whose contents match several copies
of the same release is named by the one whose packaging differs least from it: the original, not the
`commons-collections` that `org.lucee` republishes. The rest are listed with the file
(`also_published_as`), and advisories filed under any of them count for the component, marked with the
coordinate they name.

### Output

| File | Content |
|---|---|
| `binwitness.json` | everything: components with evidence, locations, file hashes, published-artifact comparison, other coordinates of the same file, licenses, vulnerabilities, upgrade advice; first-party and unidentified files; warnings; data sources with fetch times |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM with vulnerabilities, identity evidence and occurrences. A component found in several different files has one entry per file, each with its hashes; first-party and unidentified jars are `file` components with their hashes. Licenses with an SPDX id are given as `license.id`. `metadata.component` describes what was scanned |
| `components.csv`, `vulnerabilities.csv` | the same in spreadsheet form, UTF-8 with a byte order mark so that Excel reads non-ASCII paths correctly. The last two columns of `components.csv` are the upgrade advice and the release family; for a family member the advice is the family's, with its own in parentheses |
| `candidates.csv` | the [NVD candidates](#nvd-candidates), one row per record and component. When candidates were not looked for, a single row says why |

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

### NVD candidates

A finding is an advisory that names the component's package. Some CVEs never get one: GitHub leaves its
advisory unreviewed, or has none, and NVD describes the CVE only by product, as a CPE (`vendor:product`)
with a version range. binwitness links a package to a CPE when the CVEs OSV attributes to the package
show it, and lists the CPE's other NVD records that cover the component's version as candidates. In the
example at the top, 22 of the 34 components have a learned CPE, and two records come up:

- CVE-2023-35116 on jackson-databind 2.9.10, through the CPE `fasterxml:jackson-databind`. 77 of the
  package's 77 CVEs with a CPE carry it. NVD marks the record as disputed: the vendor does not accept it
  as a vulnerability.
- CVE-2026-62380, through `netty:netty`, the one CPE NVD uses for every netty module. The record's text
  names the module, `io.netty:netty-codec-socks`, so the 16 other netty modules are left out. It stays on
  netty-all, whose jar holds the two classes the record names, and reaches the netty-codec-socks inside
  netty-all by name: that module has no CVE of its own to learn a CPE from.

A CPE is linked with a package when all of these hold:

1. it is on at least 30% of the package's CVEs that NVD gives a CPE, and on at least half as many as the
   package's most frequent CPE (one product can go by several names);
2. at least half of its CVEs that OSV attributes to any package belong to the package's project or a
   subproject of it (for Maven, the groupId cut to its first three parts, so that `org.apache.tomcat.embed`
   counts as Tomcat's; for npm, the scope): a product that bundles libraries collects the CVEs of many
   projects;
3. it is on at least a quarter of the project's CVEs that NVD gives a CPE;
4. of the package's CVEs that carry it and give versions on both sides, on at least half NVD's versions
   for the CPE meet OSV's for the package: the same fix, or a version either side names (a bound, a listed
   version) that both cover. A product that bundles the package numbers its own releases (a suite at 10.x
   shipping a library at 2.x), and no version of the package falls in them. The summary counts the links
   refused this way.

Package names are never compared with product names. A package with no such history gets no candidates,
and the summary counts it as not checked. A link learned from a single CVE is marked as resting on one
CVE, the weakest kind.

An artifact relocated to new coordinates is the same library published on under them, and a CPE learned
for either stands for both: `com.mysql:mysql-connector-j` has too few CVEs of its own to learn one, and
`mysql:mysql-connector-java`, which it took over from, has plenty. Only the last POM of the old coordinates
says so (`<distributionManagement><relocation>`), and that version has no jar. binwitness reads it (and,
for the other direction, the component's own) for a package OSV has advisories for under the same
artifactId and another groupId, or under one that differs only in how far its last word goes (`-j`,
`-java`), and only when that package has a CPE the component lacks. Such pairs are reached by a "link
learned for relocated coordinates"; `learned_for` and `relocated_by` name the package the link was learned
for and the POM that says it moved. The summary counts the POMs that could not be read; in an offline scan
those are the ones not in the cache.

A record is left out when NVD rejected it, when an advisory in any installed OSV dataset attributes the
CVE to a package (withdrawn advisories included), when the scan already reports it, under its own id or
an alias, or when its CPE is for another language runtime (`target_sw` such as `node.js` on a Maven
package). Records NVD marks as disputed are kept and flagged. A CPE that NVD lists only together with
another product (a platform) is marked as conditional.

The record's text is read for what it names. When it names Maven modules of the package's project, by
coordinates (`groupId:artifactId`) or by an artifactId that carries a build (`bcpkix-fips`,
`bcpkix-jdk18on`), the candidate is kept to those modules, in whichever build the scan has: it reaches
them even where no CPE could be learned for them, and leaves out the project's other modules, except a
jar that holds a class the record names (an all-in-one jar). A build named on its own is placed by the
groupIds that OSV and the jars at hand know for its module, and the hash index when it is installed; one
that cannot be placed is ignored. A module that the package's own name begins with still counts for it
(`bc-fips`, the provider of the FIPS edition, for `bcprov`), so a near miss keeps a pair rather than
drops it. An artifactId named without a build (`camel-http`) takes nothing out: such a record often names
the path a flaw is reached through, while the flaw lives in a shared module. The summary counts the pairs
left out. Five more things are flagged, never acted on:

- same flaw as a finding: the record cites a CVE of one of the component's findings, or that finding's
  record cites the candidate (a copy of a flaw in another product gets a CVE of its own);
- names only another language: the record names a binding in another language (the Go client, the C
  library) and none in the package's own. In a list of bindings a language counts however it is written
  ("go bindings", "nodejs and D lang bindings"), JavaScript included, which elsewhere in the record of a
  Java library is too common to tell anything. Java ME is another language;
- named classes not in this jar: the record names classes (`org.example.Foo`, or a name of three or more
  words such as `UrlFilenameViewController`) and the jar holds none of them. Case is ignored and relocated
  (shaded) copies count. When the jar holds one of them, the others are not listed: a record often names
  a JDK class or one of the application's beside the flawed one, and classes in `java.*` are never
  missing. A two-word name counts as a class only when some jar of the scan has a class by that name, and
  counts as missing only when the record names a member of it (`HTTP2Flusher.terminated`) or the fix changed it:
  `BigInteger` is the JDK's. A library shaded into another jar (netty-codec-mqtt inside netty-all) holds
  the classes whose folders include every word of its artifactId and end in one of them
  (`io/netty/handler/codec/mqtt`); a class no single library of the jar owns that way may be any one's,
  and is not missing for any of them. A class can also be missing because the record names one of another
  library (a gadget in a deserialization flaw), or one that came in a later version than the one in use;
  then the flaw is not in this version either;
- the vendor's advisory names another module: with the `spring` dataset installed, Spring's own advisory
  of the CVE names modules of the project, and not this one. The modules it names are reached by name, as
  if the record named them, but no pair is left out for it: a vendor may name the module a feature is used
  through rather than the shared one the fix changed (the fix of CVE-2025-41232 changed only
  `spring-security-core`; the advisory names `spring-security-aspects`). Of the Spring advisories that
  name modules and that OSV attributes too, 23 of 137 name none of the packages OSV does (October 2026);
- none of the classes its fix changed in this jar: with the `fixes` dataset installed, the GitHub commits
  the record cites in the project's own repository are read for the main-code classes they modified,
  deleted or renamed (by their names before the fix; from the commits NVD tagged as the patch when it
  tagged any), and the jar holds none of them. Main code is `src/main/java`, or `java/` in an Ant build
  such as Tomcat's. For a record NVD has not analysed, the commits its CNA's record cites count in the
  repositories that the CVEs OSV attributes, under the same product name, cite; for Apache Tomcat, the
  commits its security pages list for the CVE count as well. Multi-release and relocated copies count, and
  so do classes a shaded library may hold as above. Classes the fix added are listed apart and not looked
  for, since an affected version lacks them. A jar that holds some of the classes is not flagged: a fix
  often changes a class every module shares as well. A class can also be missing because it had another
  name in an older version, and a commit cited as the fix is not always the fix itself. In the candidates
  of the delivery below, 102 of 656 pairs were flagged; none of the 73 of them judged on review was real
  or plausible. Of the 70 pairs that Apache Tomcat's records reached in three deliveries, the 39 on a
  module the fix did not change were flagged, and none of the others.

Candidates are leads for manual review. A CPE names a product, and a product can be wider than the
component: one CPE may stand for every module of a framework, as with netty above, or for a vendor's
drivers in several languages. They are not counted with the findings, do not take part in `--fail-on`,
and are left out of `sbom.cdx.json` and `vulnerabilities.csv`. They are written to `binwitness.json`
(`candidates`, and the evidence of each link in `candidate_links`) and to `candidates.csv`. There the
learned-link column reads like `3/6 / 3/4 / 3/6; versions meet on 3 of 3`: the package's CVEs with the
CPE out of those with any CPE, the CPE's attributed CVEs of the same project out of all its attributed
ones, the same as the first for the whole project, and on how many of the CVEs it was learned from that
give versions on both sides the versions meet. The next column lists the CVEs the link was learned from.
Further columns say how the pair was reached (a learned link, one learned for relocated coordinates, named
in the record, named in the vendor's advisory, or one of the ways of the
[CNAs' records](#before-nvd-the-cnas-records)) and whose
versions decided it, name the CNA, the product its record names and the day it published the record, list
the modules the vendor's advisory names and the classes the fix changed (with those the jar holds, and the
commits they were read from), and give the flags.

Candidates are also where a new CVE shows up first. A CVE is often published with a CPE weeks or months
before an advisory names its package. In the candidates of one delivery of about 1,100 jars, scanned in
late October 2026, 37 records were judged real or plausible on review for at least one component; 30 of
them were published from June 2026 on, and 36 had only an unreviewed GitHub advisory. The CNAs' records
brought 64 more that NVD had given no CPE yet, 47 of them published in October 2026; of the 40 judged on
review, 32 were real or plausible for at least one component.

Candidates come from local copies, in every lookup mode: the `nvd` dataset and the OSV dataset of
each ecosystem (`binwitness db sync nvd vulns`), and the `cvelist` records, the `spring` advisories and
`fixes` when installed. Only the POMs that tell a relocation are read from the Maven repositories, or from
the cache in an offline scan.
An online scan takes its findings from the online services and its candidates from these copies. Their
dates are given in the summary and in every row of `candidates.csv`. Without the copies, the summary says
candidates were not checked, never that there are none. NVD records still awaiting analysis have no CPE
yet; the summary counts them by status.

### Before NVD: the CNAs' records

NVD gives a record its CPEs days to months after the CNA (the organisation that assigned the CVE: Apache,
GitHub, VulnCheck and some 500 others) published it, and defers many for good. Until then the CNA's own
record is all there is. With the `cvelist` dataset installed, binwitness reads these records, as the CVE
Program publishes them in [cvelistV5](https://github.com/CVEProject/cvelistV5), for CVEs that OSV
attributes to no package. A record reaches a component in one of four ways, given as the `basis` of the
pair:

| `basis` | The record reaches the component |
|---|---|
| `cna_package` | by the package it names: `groupId:artifactId`, or a Maven repository URL whose path is the coordinates of a package OSV or the hash index knows. Other builds of the module are reached as for a record that names coordinates |
| `cna_cpe` | by a CPE it carries that is linked with the package, as above |
| `cna_learned` | by its product name, linked with the package the way a CPE is: by the four conditions above, from the CVEs OSV attributes and whose CNA records name one product. Names are compared in words, so "The Eclipse Foundation / Eclipse Jetty" and "eclipse / jetty.project" are the same product. A link learned from a single CVE must also read as the package: a word of the product name, other than words such as java, server or apache, is a word of the artifactId |
| `advisory_direct` | with the `spring` dataset installed, Spring's advisory of the CVE names the module and gives the affected versions |

A CPE or a product name stands for a package only while NVD has not analysed the record, and not for a
record that names its packages. A record NVD has analysed whose CPEs are not linked with the package is
mostly about another product. Taking the product name for it in October 2026 would have reached the ACS
AEM Commons library with 1,023 records of Adobe Experience Manager, and the Java driver with 19 of
Oracle's "MySQL Connectors", which are about Connector/Python. The package and the advisory name a module
on any record, unless NVD's CPEs for the record are linked with the component; then NVD's versions
decide. A pair is given once, by the first way that reaches it: NVD's learned links, a module the NVD
record or the vendor's advisory names, then the four ways in the table's order. `versions_from` says whose
versions decided (`nvd`, `cna` or `advisory`), and `record_from` whether NVD has the record with a CPE
(`nvd`) or only the CNA's is there (`cna`). Every candidate gives the CNA's short name and the dates of its
record (`cna`, `cna_published`, `cna_updated`).

Versions are read in the terms of CVE JSON 5. A range that covers the version gives its status, an
unaffected one first. Outside every range, the record's default status decides: `affected` makes the
version affected, except beside ranges with an upper bound, where a later version is as likely one the
vendor did not look at as one it found affected; `unaffected` makes it not affected; `unknown`, or no
default, does not tell. **A version the default calls unaffected is one the vendor did not list, not one
it found safe**: a CNA usually lists the release lines it supports, and older lines may have the flaw
unremarked. A record that does not tell is not given, and the summary counts the pair as left out. Git
commit ranges are not read. A range typed `semver` whose versions are Maven's (Tomcat's `9.0.0.M1`) is
compared as Maven versions, and a range that starts at a product named in words ("Apache Ant 1.9.x" up to
1.9.15) starts at the release line the words give.

The flags of NVD's records apply as well, read from the CNA's description and the program files it names,
and one more:

- only on a line below those listed (`below_listed_lines`): the record gives affected ranges on two or
  more release lines, and the version is affected only by the range from the first version up, on a line
  older than the one that range ends on. The vendor listed the lines it supports and swept older ones in
  without looking: Spring's advisory of CVE-2026-47857 lists reactor-core up to 3.4.41 and lines 3.5 and
  3.8, which flags 3.3.13. A single range from the first version up is not flagged: that is the vendor
  saying every earlier version is affected.

Pairs reached by a CPE or a product name are also left out when the record's text names another module
of the project, as for NVD's records, or when the CNA's package name is an artifactId stem that leaves the
build out (Bouncy Castle writes `bcprov`, `bcpg`). The summary counts the pairs left out by reason and the
pairs by `basis` and by `versions_from`.

### Upgrade advice

For each vulnerable component, binwitness reads every advisory of its package and the list of versions
actually published, and works out which release leaves the findings behind. The result is the `upgrade`
block of the component in `binwitness.json`, the `upgrade` column of `components.csv` and the
`binwitness:upgrade` property in the SBOM; the summary's worst findings show it too.

| Verdict | Meaning |
|---|---|
| `upgrade` | a later release on the same major line is outside every advisory of the package |
| `upgrade-across-major` | only a later major line leaves out more advisories; compatibility is not assessed |
| `partial` | the best release on this line still falls inside some advisories, and no other line does better |
| `relocated` | the artifact moved to new coordinates (its POM says so), and a release there leaves out more advisories than any release of the old ones: `target_package` names them, `same_coordinates` keeps the advice for the old ones |
| `no-published-fix` | no published version of this coordinate leaves out more advisories (log4j 1.x): replace or remove it |
| `remove-malicious` | a malicious package: remove it; no version of it is an upgrade |
| `unverified` | the version list or the advisories could not be read; the advisories' own fixed versions are listed, unchecked |

How the target is chosen:

- The candidates are the published versions later than the one in use. Pre-releases are left out unless
  the version in use is one, and so are deprecated npm versions. When only a pre-release would leave out
  more, a caveat names it.
- Each candidate is checked against all of the package's advisories, including those that do not affect
  the version in use, so the target is not a version that a later advisory covers. The winner has the
  fewest remaining findings, weighted by severity (one critical outweighs any number of highs; an unrated one counts as medium); among
  equals, the lowest version.
- A line is the first number of the version (`2.x`); calendar versions (`20231013`) form one line, and
  each npm `0.y` is a line of its own. When only a later line does better, the verdict is
  `upgrade-across-major`, and the best release on the current line is given as well.
- A fixed version that an advisory names but that was never published (a branch that stopped receiving
  releases, or a fix filed under the package's old name after it moved) is listed in
  `fix_versions_not_published` and never proposed.
- Variant builds keep their variant: `33.0.0-jre` is proposed for a `-jre` guava, not `-android`. When the
  version in use has no variant and the best target is one (`1.2.83_noneautotype`), a caveat says so and
  names the alternatives. Variant builds that do equally well are all named (`33.7.2-android or 33.7.2-jre`).
- Maven artifacts of one group at one version (`spring-core`, `spring-web` and `spring-webmvc` 5.3.4) are
  released together and upgraded together, so they form a release family with one target: a version every
  member is published at, chosen by the advisories of all of them. Families are listed in
  `upgrade_families`, each member names its family in `upgrade_family`, and `per_member` shows what each
  member would need on its own. When some members stop being published, a caveat says so.
- Caveats state what the advice does not know: a component bundled inside another artifact has to change
  with its host, a modified jar may carry local changes, declared coordinates are unverified, a finding
  that came through another coordinate of the same file has its fixed versions listed separately, a
  development dependency may not ship, and a target whose license is more restrictive than the version
  in use, or not one binwitness classifies, is named with both (`license-changes`: Elasticsearch 7.11 went
  from Apache-2.0 to Elastic-2.0 or SSPL-1.0). Both sides are read from the registry, only when licenses
  are looked up.

Version lists come from `maven-metadata.xml` on Maven Central (through `--maven-mirror` when given) and
the `--maven-repo` repositories, and from the npm registry. With the local hash index installed, `auto`
uses the index when it contains every fixed version the advisories name; the advice then says the list
is as of the index's date. In `local` mode the index is the only list, so a fix it does not contain makes
the verdict `unverified`, not `no-published-fix`; npm advice needs the registry or a cached answer.

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
| `nvd` | NVD CVE records that name an application (CPE), for [candidates](#nvd-candidates) | 235 MB download, 225 MB on disk; then 15 MB a day |
| `cvelist` | CVE records as their CNAs published them ([cvelistV5](https://github.com/CVEProject/cvelistV5)), for [candidates NVD has given no CPE yet](#before-nvd-the-cnas-records); needs `osv-maven` | 650 MB download, 130 MB on disk; then about 5 MB a day |
| `spring` | The Spring projects' security advisories ([spring.io](https://spring.io/security)), for the modules and versions each names, for [candidates](#nvd-candidates) | 260 kB download, 140 kB on disk |
| `fixes` | The classes changed by the GitHub commits that CVE records cite as their fix, or that Apache Tomcat's security pages list, for [candidates](#nvd-candidates); needs `nvd` and `osv-maven`, and `cvelist` for the commits the CNAs' records cite | about 430 commits from github.com: 8 MB download, 0.35 MB on disk |

Groups: `vulns` (both OSV datasets and `kev`), `java` (`osv-maven`, `kev`, `maven-hashes`), `all` (these,
`nvd`, `cvelist`, `spring` and `fixes`).
Datasets live in `~/.cache/binwitness/datasets` (`--db-dir`, or `$BINWITNESS_DB`).

Updates are incremental where the publisher allows it. OSV keeps a list of records by modification time,
so an update fetches only the records changed since the previous one. If more than 5,000 records have
changed, or the last full download is a month old, the archive is downloaded again instead; that also
drops records deleted upstream. The KEV catalog and the Spring advisories are small and fetched whole;
spring.io amends advisories without dating the change, so the Spring copy is replaced whenever its
content differs. A commit does not change once made, so each one is fetched once; a later sync fetches
only the commits cited by records new since. The commits the CNAs' records cite are read only when
`cvelist` is installed: sync it before `fixes` (`all` does). A sync that brings new records of `osv-maven`,
`nvd` or `cvelist` without syncing `fixes` says how many commits they cite that `fixes` has not read. GitHub limits what one address may fetch: the commits are
read a few at a time, and when GitHub stops answering, the sync keeps what it has and the next one goes
on from there. The Tomcat security pages are read whole at each sync.

NVD publishes one feed per year and a feed of the records modified in the last eight days. The first sync
reads every yearly feed; later ones read only the modified feed, as long as the copy is less than seven
days old, and skip it when its digest has not changed. An older copy is built again from the yearly
feeds. Each feed is checked against the SHA-256 that NVD publishes next to it. A copy stored by version
0.4.3 or earlier lacks the tags NVD gives the fix commits, and is downloaded again in full at the next
sync (about 235 MB); the copy held stays in use until that is done, and whenever there is no connection.

The CVE Program publishes cvelistV5 as a snapshot of every record each midnight, the changes of each day,
and those of each hour since midnight. The first sync of `cvelist` downloads the latest snapshot (about
650 MB) and the hour's changes; later ones
apply the changes of each day the copy lacks (about 5 MB a day) and the latest hour's. The daily changes
are kept for at least seven weeks: a copy more than 40 days behind, or one that lacks a day no longer
published, is downloaded again. Of about 400,000 records, the text is kept only of those that may reach
a Maven package (about 39,000): those OSV attributes, those that name a Maven package or a CPE, those
that name a product a CVE OSV attributes names, and those a vendor's advisory names. Of the others, the
id, the CNA, the dates and the product names are kept. When OSV's attributions make a product known
later, the texts of its records are fetched one by one from the repository, at most 1,000 at each sync;
`db status` says how many are still to fetch. A sync reads the repository's feed of releases first, and
does nothing more when the copy is at the latest one and OSV's attributions have not changed since.

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

A large file (the OSV archives, the cvelist snapshot, the hash base) is fetched in pieces of 8 MB over four
connections when its server sends ranges: one connection is often held far below what the line gives, and
a slow one then holds up a piece, not the file. Once no piece is left to start, a free connection fetches
the rest of a piece going at under half the typical speed a second time, and the piece is taken from
whichever fetch finishes first; the bytes fetched twice stay within one piece. A dropped connection resumes
where it stopped, and a sync
that gives up resumes on the next run, unless the file has changed in between. If a sync fails, the copy already installed is kept. Only one `db sync` or `db remove` runs on a directory at a
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

With the hash index installed, a jar it lists is named from the jar and the index alone, never from
deps.dev or the cache, so a `local` scan names a jar the same way whatever the cache holds, and `auto` names
it as `local` does. A jar the index does not list is looked up on deps.dev, which lists every coordinate of
a file but leaves out classifier jars (`json-lib-2.4-jdk15.jar`), then on Maven Central search. Where the
index lists only a republication and the jar carries no clue to the original, a `local` and an `online`
scan can still differ in a component's name.

The result records which local datasets were read and how current they were (`data_sources.local`),
also in an `online` scan, whose candidates come from them; where the findings came from is `options.lookup`.
A dataset last synced more than seven days ago produces a warning.

Each dataset is downloaded by your machine directly from its publisher, under the publisher's terms: OSV
from Google's public bucket (each record carries the license of the database it comes from), the hash
index from Aqua Security's `trivy-java-db` image on ghcr.io and from Maven Central's index, the KEV catalog
from CISA, the CVE records from NVD's data feeds and the CVE Program's cvelistV5 repository on GitHub,
the Spring advisories from spring.io, the fix commits from github.com and Tomcat's security pages from
tomcat.apache.org. binwitness uses
NVD data but is not endorsed or certified by the NVD.

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

When the scan has [candidates](#nvd-candidates), a finding of the other tool that is also a candidate of
this scan for the same component carries the CPE in `candidate_cpe`, and the summary counts them per
class. These are typically the `unattributed` and `no-github-record` ones.

A GitHub token raises the API limit from 60 to 5,000 lookups per hour. binwitness reads it from
`GITHUB_TOKEN`, from `GH_TOKEN` or from `gh auth token`.

## MCP server

`binwitness mcp` lets an AI assistant run scans and read their results through the
[Model Context Protocol](https://modelcontextprotocol.io), over stdio. It needs the optional SDK
(`pipx install "binwitness[mcp]"`, or `pip install "binwitness[mcp]"`).

```
binwitness mcp --root ~/deliveries --lookup local
```

| Option | Purpose |
|---|---|
| `--root DIR` | a directory whose files the assistant may scan or cross-check (repeatable). Paths are resolved, symbolic links included, and must lie inside one. Without a root, only results opened by path can be read |
| `--lookup auto\|local\|online` | the most a scan may use; a tool call can ask for less, never more. With `local`, nothing leaves the machine and `crosscheck` is not offered. Default `auto` |
| `--allow-class-search` | let scans use `--class-search`, which sends class names (off by default) |
| `--results DIR` | where scans are written (default `~/.local/share/binwitness/scans`, on Windows `%LOCALAPPDATA%\binwitness\scans`) |
| `--cache-dir`, `--db-dir`, `--maven-mirror`, `--maven-repo`, `--workers`, `--max-age` | as for `scan` |

Claude Code:

```
claude mcp add binwitness -- binwitness mcp --root /home/me/deliveries --lookup local
```

Claude Desktop, Cursor and other clients configured with an `mcpServers` JSON file take the same command:

```json
{
  "mcpServers": {
    "binwitness": {
      "command": "binwitness",
      "args": ["mcp", "--root", "/home/me/deliveries", "--lookup", "local"]
    }
  }
}
```

| Tool | What it does | Sends |
|---|---|---|
| `start_scan` | scans files under a root in a separate `binwitness scan` process and returns a scan id at once; one scan at a time | what `scan` sends at the lookup level chosen |
| `scan_status` | running (elapsed time, last progress line), finished, or failed (the end of the log) | nothing |
| `open_result` | registers a `binwitness.json` made earlier and gives its overview | nothing |
| `list_scans` | scans in the results directory and results opened in this session | nothing |
| `overview` | counts, the worst findings with advice, upgrade verdicts, license families | nothing |
| `list_components` | one line per component, filtered by text, severity, ecosystem, license family or verdict; 20 per page, at most 100 | nothing |
| `list_unidentified` | jars the scan could not name, with the reason | nothing |
| `get_component` | one component by purl or by its full name: evidence, files, findings with fixed versions and advice, upgrade advice; locations on request. A part of a name gets the names that contain it, never one of them as the answer | nothing |
| `get_vulnerability` | one finding with its OSV record: details, ranges, references | the advisory id to OSV, when the local datasets lack the record and lookups are allowed |
| `upgrade_plan` | steps, worst first: remove, upgrade, replace, or change the host of bundled components; each says what it clears, what remains and its caveats. A release family is one step; its `per_member` lists the members with a target of their own or findings left | nothing |
| `list_candidates` | the scan's [NVD candidates](#nvd-candidates), those with an unflagged component first, then worst first, filtered by text (component, CPE or the product a CNA's record names), severity, or without the disputed ones | nothing |
| `get_candidate` | one candidate: the NVD record as of the last sync, or the CNA's where NVD has given no CPE (status, description, CVSS, CWE, references, the CNA and its dates), the components it reaches with the version range and whose it is, each one's flags, how each CPE was learned, and what to check before taking it as a finding | nothing |
| `crosscheck` | classifies another scanner's export against a scan and saves the full report | what `crosscheck` sends; not offered with `--lookup local` |

Every answer about a result starts with `coverage`: whether every lookup succeeded, what was not
identified or not checked, which lookups were off, the data sources and their dates, the binwitness
version that scanned and the one serving. It also states what the result cannot say: a component without
findings has no advisory in the data used as of its date, which is not evidence that it has no flaws, and
there is no reachability analysis. The upgrade plan adds that compatibility with the application is not
checked, that a Maven dependency's version is often set by a BOM or parent POM, and that an npm package
may be a dependency of a dependency. Candidates are presented as leads for review, kept out of finding
counts, with the points to check when an assistant gives a first judgment of one. Lists are paged and file locations are counted, not listed, unless
asked for, so that answers fit an assistant's context.

## What leaves your machine

binwitness sends the following to public services:

- SHA-1 hashes of jars, and SHA-256 hashes of JavaScript files that may be copied libraries (the project's
  own plain sources and build configuration are not looked up)
- component coordinates and versions
- CVE identifiers
- for upgrade advice, the names of vulnerable packages: to OSV for all of their advisories, and to Maven
  Central, the `--maven-repo` repositories or the npm registry for their published versions
- with `--class-search` only: one fully qualified class name for each jar that nothing else identified,
  and the coordinates its file name and manifest suggest. Classes under `--first-party-group` prefixes are never sent. An unidentified jar may be private code,
  so its class name can reveal a package name. Leave the option off when that matters.

It never uploads file contents. First-party jars are not looked up. With `--maven-mirror`, requests for
Maven Central files go to the mirror instead, so its operator sees which coordinates you checked. The
operators of `--maven-repo` repositories see the coordinates asked of them in the same way. With
`--lookup local` nothing is sent at all. The MCP server sends only what the scans and tools it runs send. `binwitness db sync` only downloads public datasets and sends nothing about your files. To
scan a machine with no internet access, copy the dataset directory and, optionally, the response cache
(`--cache-dir`, default `~/.cache/binwitness`) from a connected one.

| Service | Used for |
|---|---|
| [deps.dev](https://deps.dev) | jar hash to coordinates; licenses |
| [Maven Central](https://central.sonatype.com) | hash search fallback; published checksums; POM licenses; `--class-search`; version lists for upgrade advice; the modules of a groupId for `crosscheck` |
| repositories given with `--maven-repo` | checksums, jar directories, POM licenses and version lists of releases Central does not have |
| [OSV.dev](https://osv.dev) | vulnerabilities (GitHub Security Advisories and others); all advisories of a vulnerable package, for upgrade advice |
| [npm registry](https://www.npmjs.com) | published versions of vulnerable npm packages, for upgrade advice, and of packages a JavaScript file matched |
| [jsDelivr](https://www.jsdelivr.com) | JavaScript file hashes; file lists of the releases next to a match |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | known exploited flag |
| [OSV data bucket](https://google.github.io/osv.dev/data/) | `db sync` of the OSV datasets |
| [ghcr.io](https://github.com/aquasecurity/trivy-java-db) | `db sync` of the Maven Central hash index |
| [Maven Central index](https://repo1.maven.org/maven2/.index/) | `db sync`: weekly additions to the hash index |
| [NVD data feeds](https://nvd.nist.gov/vuln/data-feeds) | `db sync` of the `nvd` dataset |
| [Spring security advisories](https://spring.io/security) | `db sync` of the `spring` dataset |
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | `db sync` of the `cvelist` dataset: snapshots and changes from github.com, single records from raw.githubusercontent.com |
| [GitHub commits](https://github.com) | `db sync` of the `fixes` dataset: the diff of each commit a candidate's record or Tomcat's security pages cite |
| [Apache Tomcat security pages](https://tomcat.apache.org/security.html) | `db sync` of the `fixes` dataset: the commits each lists for a CVE |
| [GitHub advisories](https://github.com/advisories) | `crosscheck` only |

## Limitations

These limits are deliberate, so read them before relying on a result:

- **Local matching uses binwitness's version ordering.** Advisory ranges in a local dataset are
  evaluated by binwitness's implementation of Maven and semver ordering, the online API by OSV's own.
  They agree on ordinary versions; unusual version strings can compare differently.
- **Advisory coverage is that of OSV.** An advisory that names no package (GitHub "unreviewed",
  NVD-only CPE records) cannot be matched to a component, and is at most a
  [candidate](#nvd-candidates) for a component whose CPE or product name could be learned. Vendor-private
  and national vulnerability databases are not consulted. Treat counts as a lower bound. `crosscheck`
  against a commercial tool's output is the practical way to see what such a database adds.
- **Candidates are read from the records' words.** The text and fields of a record are matched, not
  understood, and some readings are known to fail. Languages are read from the description only, not from
  the package name or repository a CNA's record gives, and a language written in lower case counts only in
  a list of bindings. Names written like classes that are not Java classes (TLS messages, native
  functions) are taken for classes the jar lacks: in the delivery of about 1,100 jars above, 8 pairs of two
  records on builds of netty-tcnative are flagged so, although the records name that package. A library
  shaded into another jar does not hold the classes in folders that do not spell its artifactId
  (netty-handler's `io/netty/handler/ssl`), so they are never missing for it, and its pairs are flagged
  less. A class the fix changed may have had another name in an older version, so a pair on an old
  version can be flagged although the flaw is there; a fix that changed no Java code flags nothing; and a
  commit that merges many changes is read whole as the fix.
- **Identification needs a published artifact or a declaration.** A private build, a fork or a relocated
  copy of a library with no `pom.properties` stays unidentified, unless the same delivery also carries a
  copy that was identified (or `--class-search` finds it). A release that only another repository
  publishes (a milestone, a vendor's own build) needs `--maven-repo`. Each unidentified jar states why and
  shows what its manifest or file name suggests (`hint`), unverified. Classes shaded without their
  `pom.properties` are not recognised; binwitness does no bytecode or source fingerprinting. Content
  matching compares CRC-32 values. It catches rebuilds and ordinary edits, not a deliberately forged
  collision. Jars that hold only a manifest, a license and a notice (Spring Boot starters) look alike
  across artifacts; they are never matched by content and are reported as holding no code. Classifier jars (`-linux-x86_64`) are compared only with the main artifact.
- **Upgrade advice is about advisories, not compatibility.** It says which published version is outside
  the package's advisories in OSV. Whether the application builds and runs with it, whether the version
  is set by a BOM, a parent POM or another package, and whether the affected code is reachable are not
  assessed. A version published after the version list was read is not considered.
- **Front-end bundles are opaque.** Code that webpack or rollup merged into chunks cannot be matched by
  hash. Ship the lockfile, or the `node_modules` the build used, alongside the bundle. Banner comments
  give only partial coverage. Recognised bundles are counted apart (`bundled_scripts`) so that they are not
  taken for unknown libraries.
- **Ecosystems: Java (Maven) and JavaScript (npm).** OS packages, Python, Go, .NET and native libraries
  are out of scope; use Trivy or Syft for an image's OS layer. Their dependency files are named in a
  warning. JDK/JRE runtime jars are skipped.
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
pip install -e ".[test,mcp]"
pytest
```

Tests build their own archives and answer network calls from scripted responses; they never touch the
internet. The MCP tests skip themselves when the SDK is not installed; one of them starts `binwitness mcp`
over stdio and runs a scan through it.

## License

Apache-2.0
