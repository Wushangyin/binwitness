# binwitness

[English](README.md) · **简体中文**

面向**实际交付物**的软件成分分析：jar、war、`docker save` 镜像、zip 包和前端构建产物，不论嵌套多少层都会逐层拆开。结果中的每个组件都附带识别它的证据，报告的每一行都经得起追问。对每个有漏洞的组件，它会指出离开该包全部公告的最近已发布版本。binwitness 还能用公开漏洞数据逐条核对其他扫描工具的结论，并为每一处分歧归类；[MCP 服务](#mcp-服务)让 AI 助手可以发起扫描、阅读结果。

```
$ binwitness scan release.zip -o out
walked 1 input(s): 5 distinct jars, 0 npm package entries, 0 distinct scripts
identified jars: 5 of 5
vulnerabilities: 133 distinct across 22 components
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
  ... 75 more (vulnerabilities.csv)
upgrades     upgrade on the same line 22; 2 advisories name a fixed version that is not published
licenses     permissive 34
```

示例中的 `release.zip` 装有从 Maven Central 下载的五个 jar：log4j-core 2.14.1、jackson-databind 2.9.10、commons-collections 3.2.1、mybatis 3.4.6 和 netty-all 4.1.54.Final。扫描从中识别出 34 个组件：netty-all 内含的 27 个模块，以及 shade 进 mybatis 的 ognl 和 javassist。`netty-all` 本身名下没有任何漏洞公告，它的模块名下有 71 条。摘要先列最严重的发现（恶意包、已知被利用、严重、高危），全部发现见 `vulnerabilities.csv`。每条都附上离开该包全部公告的最近已发布版本：jackson-databind 给的是 2.18.11，而不是修复其第一条发现的 2.9.10.1，因为此后几十条公告同样覆盖 2.9.10.1（见[升级建议](#升级建议)）。（数字基于 2026 年 10 月的数据，会随新公告的发布而增长。）

## 为什么还要一个 SCA 工具

Trivy、Syft/Grype 和 OSV-Scanner 在识别 jar、报告漏洞方面都做得很好。binwitness 面向的是另一种角色：接收别人的交付物、并要为检查结果签字负责的审查者。

- **只认证据，不靠猜测**。一个组件被识别出来，要么因为文件与某个已发布构件逐字节相同（`exact`），要么因为其中每个条目都与已发布构件逐条对上（`content`），要么因为构件自己声明了坐标（`declared`）。从不由文件名推断坐标。其余一律列为未识别，并附上它携带的线索。
- **区分重新打包与被修改**。fat jar 构建常把依赖重新压缩：删掉目录条目、改写 manifest、时间戳也变了。文件哈希因此对不上，但代码并没有变。binwitness 读取已发布 jar 的中央目录（用 Range 请求只取文件末尾几 KB），逐条比较每个条目的 CRC-32 和大小。只有 manifest、jar 索引、签名或 `META-INF/maven` 下的 Maven 构建元数据不同的，判为 `repackaged`；类或资源文件不同的，判为 `differs`，并列出改动、新增和缺少的条目。打在另一个 jar 里、而外层 jar 与其发布件完全相同的，判为 `inside-published`：那是上游自己放进去的。
- **拆开捆绑在一起的代码**。fat jar（`BOOT-INF/lib`、`WEB-INF/lib`）、shade 过的 jar（内嵌 `pom.properties`）以及 `netty-all` 这类合集构件，都会展开成各自的模块。漏洞公告登记在模块名下，只按 `netty-all` 自己的名字查会全部漏掉。
- **能核对其他扫描工具的结论**。`binwitness crosscheck` 读入另一个工具的结果，对其中 binwitness 没有复现的每条发现，到 GitHub 已审核的漏洞库里查原始公告，再归入以下一类：确属漏报、属于同一项目的另一个模块、属于另一个包、版本不在受影响范围内、上游登记时未指明任何包。按产品名（CPE）匹配的工具会把一条公告挂到同一产品的所有模块上，这个命令能看出一份报告里有多少是这类噪声。
- **升级目标经过核实，不照抄公告**。公告里的「修复版本」只是某一个缺陷的首个修复。binwitness 读取该包的全部公告和实际发布过的版本，给出离开所有公告的最近版本。公告写了、但从未发布的修复版本会如实列出，从不作为建议。
- **结果注明数据时效**。每个响应都连同获取时间一起缓存，结果中记录每个数据源用到的最旧和最新数据。`--offline` 可以在不联网的机器上用缓存重放一次扫描。
- **联网、本地，或两者结合**。漏洞库和 Maven Central 的哈希索引可以保存在本地并增量更新，这样识别 jar、匹配漏洞时不必向外发送任何内容。保留多少由你决定，见[本地数据集](#本地数据集)。
- **零依赖**。只用 Python 标准库（3.10+）。可选的 MCP 服务需要 MCP SDK。

## 安装

```
pipx install binwitness
# 带 MCP 服务
pipx install "binwitness[mcp]"
# 或者安装最新提交
pipx install git+https://github.com/Wushangyin/binwitness
# 或者在克隆下来的目录里
pip install .
```

打开 rar 和 7z 压缩包需要 `PATH` 中有 `unrar`、`7z` 或 `bsdtar`，也可以用 `--unpacker` 指定。Java EE 资源适配器（`.rar`）实为 zip，不需要这些工具。

## 扫描

```
binwitness scan INPUT... -o OUTDIR [options]
```

| 选项 | 作用 |
|---|---|
| `--first-party-group com.acme` | 自有代码的 Maven groupId 前缀，可重复。不做查询，单独列出。 |
| `--first-party-jar acme-` | 自有代码的 jar 文件名前缀，可重复。 |
| `--first-party-npm @acme/` | 自有 npm 包的名称前缀，可重复。 |
| `--exclude GLOB` | 跳过某些位置，例如用 `*!/<registry/unrelated:*>` 跳过多镜像 tar 包中的某一个镜像。整个目录下的文件都会被该模式跳过时（`*/target/*`），这个目录根本不进入 |
| `--class-search` | 识别不带坐标的重新构建 jar（见下文）。每个这样的 jar 会向 Maven Central 发送一个类名，并查询其名称提示的坐标 |
| `--maven-repo URL` | 另一个发布了 Maven Central 没有的版本的 Maven 仓库：里程碑仓库、厂商或贵公司自己的仓库。在中央仓之后按给出的顺序查询校验和、jar 目录和 POM 许可证。可重复 |
| `--no-js` / `--no-licenses` / `--no-vulns` | 不查询随项目拷入的 JavaScript 文件 / 许可证 / 漏洞 |
| `--no-upgrades` | 不计算[升级建议](#升级建议)（省掉每个有漏洞的包的公告查询和版本列表查询） |
| `--fail-on high` | 发现该等级及以上的问题时以状态码 3 退出；没有发现、但扫描未能查全（查询失败或离线查不到）或什么都没找到时以状态码 4 退出（用于 CI） |
| `--unpacker PROGRAM` | 指定 rar/7z 解压程序（`unrar`、`7z` 或 `bsdtar`），默认用 `PATH` 中找到的第一个 |
| `--lookup auto\|local\|online` | 由谁回答查询，见[本地数据集](#本地数据集)。默认 `auto` |
| `--maven-mirror URL` | 从 Maven Central 的镜像获取中央仓文件（校验和、POM、jar 目录），适合离 Maven Central 较远的机器。哈希搜索和 deps.dev 仍访问各自的主机。镜像必须原样提供中央仓的文件并支持 `Range`，否则会下载整个 jar。结果会注明所用镜像（`options.mirrors`、`data_sources.online`） |
| `--offline` / `--max-age H` | 不联网，只用本地数据集和响应缓存 / 联网获取的漏洞数据超过 H 小时（默认 12）就重新获取 |
| `--workers N` | 并行查询数（默认 16）。Maven Central 搜索最多同时两个 |
| `--cache-dir DIR` / `--db-dir DIR` | 响应缓存（默认 `~/.cache/binwitness`，或 `$BINWITNESS_CACHE`）/ 本地数据集（见[本地数据集](#本地数据集)） |

检查的内容：

| 交付物中的内容 | 识别方式 |
|---|---|
| 任何 `.jar`，以及同样打包的插件和库（`.hpi`、`.jpi`、`.aar`、`.nar`、`.kar`、资源适配器 `.rar`），无论在顶层还是嵌在 fat jar、war、ear、zip、tar、镜像里 | 按 SHA-1 依次查本地哈希索引（已安装时）、deps.dev、Maven Central 搜索。都查不到时，读 jar 自带的 `META-INF/maven/**/pom.properties`，先在 Maven Central、再在 `--maven-repo` 仓库中与该坐标下的发布件比对：发布的校验和一致判 `exact`，条目一致判 `content`。 |
| 含多份 `pom.properties`、且都与文件名不对应的 jar（改过名，又 shade 了其他库） | 逐个拿声明的构件与该 jar 逐条比对，manifest 中提到的优先；发布件条目全部对上的那个就是这个 jar（`content`），其余视为包含在其中 |
| 同一交付物中已识别 jar 的改名或重新压缩副本 | 除 manifest、索引、签名和 Maven 构建元数据外，每个条目的 CRC-32 和大小都与已识别的 jar 相同：判 `content`，不发任何请求。副本的条目同时对上多个不同组件的（只改了版本号的几次发布），保持未识别，并在 `same_content_as` 中列出这些组件 |
| 以上都不满足的 jar（Gradle 构建、改名并重新压缩的），开启 `--class-search` 时 | 候选依次来自三处：取 jar 主包下的一个类到 Maven Central 搜索，并按 manifest 或文件名提示的版本缩小范围；文件名和 manifest 提示的构件名，配上该包名以及同族已识别 jar 的 groupId（`spring-core` 旁边的 `spring-jcl`）；开启 `--maven-repo` 时，再取中央仓搜索为该类列出的构件，按提示的版本查。只接受发布件条目与该 jar 对上的候选（`content`），提示本身从不直接采信。 |
| shade 过的 jar | jar 里多出的 `pom.properties` 成为包含在该 jar 中的组件（`contained_in`）。jar 唯一的 `pom.properties` 在以下情况下也这样处理：jar 的名字没有提到它，并且该构件的发布条目大半缺失（guice 只带有 cglib 的），或 jar 自有的条目比该构件还多（把整个压缩库打进去的数据库驱动） |
| `netty-all` 这类合集构件 | `META-INF/io.netty.versions.properties` 中的模块清单 |
| `package-lock.json`（v1-v3）、`yarn.lock`（classic 和 berry）、`pnpm-lock.yaml` | 锁文件列出的包；锁文件记录了 dev/runtime 范围的，一并保留。别名（`name@npm:other@1.0.0`）按实际安装的包命名。`node_modules` 里只认 npm 自己的 `node_modules/.package-lock.json`：各个包随发布带的锁文件从未被安装 |
| `node_modules/**/package.json` | 已安装的包 |
| `node_modules` 以外随项目拷入的 `.js` 文件 | 与某个 npm 发布版中的文件逐字节相同（jsDelivr）。同一个文件出现在多个版本里时，哈希索引也只报其中一个版本，所以只有前后相邻的版本里没有这个文件，或者交付物里的锁文件、`package.json` 声明的版本恰好含有这个文件时，才采用这个版本。否则把文件和查到含有它的版本列入 `scripts_without_version`，不生成组件，也不挂漏洞。文件头注释写明了发布版本、但找不到相同文件的，判 `declared`。构建配置（`*.config.js`、`.eslintrc.js`）以及 `src/`、`scripts/`、`tests/` 下的普通源码（不在资源或库目录里，没有许可证注释、UMD 包装，也未压缩）属于项目自己，不查询（`project_scripts`）。查不到的文件中，打包工具产物（webpack、Vite、Parcel 的 chunk）列入 `bundled_scripts`，其余列入 `unmatched_scripts`。 |
| 扩展名看不出格式的文件（`app.bin`、`plugin.dat`） | 看文件头：自带类文件的 zip 按 jar 检查；其他 zip、tar（含 gzip 或 xz 压缩的）、rar 和 7z 压缩包会被打开 |

容器镜像：支持 `docker save` 的 tar 包和 OCI 镜像布局（打成 tar 或解开成目录均可），多平台镜像的每个平台分别检查。按顺序叠加各层，包括 whiteout 删除标记，所以只检查最终镜像中存在的文件。属于 JDK/JRE 安装目录（`bin/java` 或 `lib/modules` 旁边有 `release` 文件的目录）的 jar 会跳过并计数。

目录输入会跟随其中的符号链接；指回已遍历目录的链接不会重复进入。大于 16 MB 的条目先写入临时文件再读取，不整个放进内存；解压后膨胀一百倍以上的条目视为解压炸弹跳过。所有被跳过的内容（失效的链接、读不了的压缩包、解压炸弹、压缩包内的链接）都会列在警告中。构建缓存会跳过，并列入 `skipped_build_caches`：带 `CACHEDIR.TAG` 标记的目录（Cargo 的 `target/`）、`.next/cache`、`node_modules/.cache`、`.angular/cache`、`.parcel-cache` 等。binwitness 不读取的生态的依赖文件（`requirements.txt`、`pyproject.toml`、`go.mod`、`Cargo.toml`、`Gemfile`、`composer.json` 等）会在警告和 `not_covered` 中点名，免得把不含这些依赖的结果当成没有问题。

同一个文件有时以多个坐标发布：项目改过 groupId（`com.oracle.ojdbc` 与 `com.oracle.database.jdbc`）、别人重新发布的副本、某个 jar 没有变化的新版本。组件名优先取 jar 自带 `pom.properties` 中的坐标（如果在其中），否则取与文件名相符的那个。内容同时对上同一版本几个副本的 jar，取打包差异最少的那个命名：是原件，而不是 `org.lucee` 重新发布的 `commons-collections`。其余坐标随文件列出（`also_published_as`），登记在其中任何一个坐标下的漏洞公告都计入该组件，并注明公告针对的是哪个坐标。

### 输出

| 文件 | 内容 |
|---|---|
| `binwitness.json` | 全部信息：组件及其证据、位置、文件哈希、与发布件的比对、同一文件的其他坐标、许可证、漏洞、升级建议；自有文件和未识别文件；警告；各数据源及获取时间 |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM，含漏洞、识别证据和出现位置。同一组件出现在几个不同文件里的，每个文件一条，各带哈希；自有 jar 和未识别 jar 作为 `file` 组件列出，带哈希。有 SPDX 编号的许可证写在 `license.id` 中。`metadata.component` 描述被扫描的对象 |
| `components.csv`、`vulnerabilities.csv` | 同样的内容，表格形式，UTF-8 带字节顺序标记，Excel 打开非 ASCII 路径不会乱码。`components.csv` 的最后一列是升级建议 |

查询失败时（服务宕机，或 `--offline` 时缓存里没有），摘要中会有一行 `INCOMPLETE` 说明哪些没查，`binwitness.json` 的 `summary.incomplete` 给出计数，没查漏洞的组件标有 `vulnerabilities_checked: false`。这些组件漏洞为零的意思是「没查」，不是「没有」。

严重等级优先取公告自己给出的等级（GitHub 的评级），没有时按 CVSS v3 向量计算。来自 OpenSSF 恶意包数据源的记录按严重（critical）计。发现按 CVE 合并，同一漏洞的 GHSA 与 CVE 只计一次。每条发现都列出各组件的修复版本；已列入 CISA 已知被利用漏洞目录（KEV）的，注明列入日期。

许可证优先从构件本身取：内嵌的 `pom.xml`、`Bundle-License` 头或 LICENSE 文件。LICENSE 会完整读取，以免漏看附在 GPL 正文之后的例外条款。构件本身没有时，依次查 deps.dev 和已发布的 POM（包括其父 POM）。许可证分为以下几类：`permissive`、`weak-copyleft`、`copyleft-with-exception`、`strong-copyleft`、`source-available`、`unknown`。许可证名称写成 SPDX 编号，并带上原文写明的版本（`The Apache Software License, Version 2.0` 写作 `Apache-2.0`，`New BSD License` 写作 `BSD-3-Clause`）。原文没说明版本或变体的，例如单写一个 `BSD`，保持原样。GPL 原文既没写「only」也没写「or later」的，沿用 SPDX 的旧编号（`GPL-2.0`、`GPL-2.0-with-classpath-exception`），不替原文多说什么。

### 升级建议

对每个有漏洞的组件，binwitness 读取该包的全部公告和实际发布过的版本列表，算出哪个版本能离开这些发现。结果写在 `binwitness.json` 中该组件的 `upgrade` 块里，也是 `components.csv` 的最后一列和 SBOM 中的 `binwitness:upgrade` 属性；摘要里的最严重发现同样带上它。

| 结论 | 含义 |
|---|---|
| `upgrade` | 同一主版本线上有更晚的版本不在该包任何公告的影响范围内 |
| `upgrade-across-major` | 只有更晚的主版本线能离开更多公告；不评估兼容性 |
| `partial` | 这条线上最好的版本仍在部分公告范围内，其他版本线也不比它好 |
| `relocated` | 构件已迁到新坐标（其 POM 写明），新坐标下有版本比旧坐标的任何版本都能离开更多公告：`target_package` 给出新坐标，`same_coordinates` 保留针对旧坐标的建议 |
| `no-published-fix` | 这个坐标没有任何已发布版本能离开更多公告（log4j 1.x）：替换或移除 |
| `remove-malicious` | 恶意包：移除，它的任何版本都不算升级 |
| `unverified` | 读不到版本列表或公告；列出公告自己写的修复版本，未经核实 |

目标版本的选法：

- 候选是比当前版本更晚的已发布版本。除非当前用的就是预发布版，否则不考虑预发布版，也不考虑已弃用的 npm 版本。只有某个预发布版能离开更多公告时，会在注意事项中点名。
- 每个候选都拿该包的全部公告来核对，包括不影响当前版本的那些，所以不会建议一个被更晚公告覆盖的版本。按严重度加权，剩余发现最少者胜出（一条严重压过任意条高危；没有评级的按中危计）；相同时取最低版本。
- 版本线按版本号的第一个数字划分（`2.x`）；日历式版本（`20231013`）算一条线，npm 的每个 `0.y` 各算一条线。只有更晚的版本线更好时，结论是 `upgrade-across-major`，并同时给出当前线上最好的版本。
- 公告写了、但从未发布的修复版本（某个分支已停止发版，或包改名后修复登记在旧名下）列入 `fix_versions_not_published`，从不作为建议。
- 变体构建保留其变体：`-jre` 的 guava 建议 `33.0.0-jre`，不建议 `-android`。当前版本没有变体、而最佳目标带变体（`1.2.83_noneautotype`）时，注意事项会说明并列出其他选择。几个变体效果相同时全部列出（`33.7.2-android or 33.7.2-jre`）。
- 同一 group、同一版本的 Maven 构件（`spring-core`、`spring-web`、`spring-webmvc` 5.3.4）是一起发布、一起升级的，因此算作一个发布族，只给一个目标：所有成员都发布过的某个版本，按全体成员的公告来选。发布族列在 `upgrade_families` 中，每个成员在 `upgrade_family` 中写明所属的族，`per_member` 给出各成员单独升级时需要的版本。有成员停止发布时，注意事项会说明。
- 注意事项写明建议本身不知道的情况：打包在别的构件里的组件要随宿主一起换；被修改过的 jar 可能带有本地改动；声明出来的坐标未经核实；经同一文件的另一个坐标查到的发现，其修复版本单独列出；开发依赖可能并不随产品交付；目标版本的许可证比当前版本更严、或是 binwitness 不认识的许可证时，两边的许可证都会写明（`license-changes`，例如 Elasticsearch 7.11 从 Apache-2.0 改成了 Elastic-2.0 或 SSPL-1.0）。两边都以包仓库登记的为准，查许可证时才核对。

版本列表来自 Maven Central 上的 `maven-metadata.xml`（指定 `--maven-mirror` 时经由镜像）和 `--maven-repo` 仓库，以及 npm registry。装了本地哈希索引时，`auto` 模式下只要索引里包含公告提到的全部修复版本，就用索引，建议中会注明列表截至索引的日期。`local` 模式下索引是唯一的列表，所以索引中没有的修复版本会让结论成为 `unverified`，而不是 `no-published-fix`；npm 的升级建议需要 registry 或缓存中的回答。

## 本地数据集

不做任何设置时，binwitness 向在线服务查询并缓存每个回答，所以缓存中恰好是你的扫描用到过的内容。也可以把整个数据集保存在本地：

```
binwitness db sync osv-maven kev      # 部分数据集
binwitness db sync all                # 全部数据集
binwitness db sync                    # 更新已安装的数据集
binwitness db status                  # 装了什么、多旧、多大、下次同步会做什么
binwitness db remove osv-npm
```

| 数据集 | 内容 | 大小 |
|---|---|---|
| `osv-maven` | Maven 包的 OSV 漏洞公告 | 下载 10 MB，占用 13 MB |
| `osv-npm` | npm 包的 OSV 漏洞公告，含恶意包报告 | 下载 210 MB，占用 250 MB |
| `kev` | CISA 已知被利用漏洞目录 | 2 MB |
| `maven-hashes` | Maven Central 上每个 jar 的 SHA-1（以 [Trivy java-db](https://github.com/aquasecurity/trivy-java-db) 打底，再加上中央仓自身索引的新增部分） | 下载 1 GB，占用 1.5 GB；之后每一两周 10-50 MB |

分组：`vulns`（两个 OSV 数据集和 `kev`）、`java`（`osv-maven`、`kev`、`maven-hashes`）、`all`。数据集保存在 `~/.cache/binwitness/datasets`（可用 `--db-dir` 或 `$BINWITNESS_DB` 指定）。

发布方允许的地方都做增量更新。OSV 维护一份按修改时间排列的记录清单，所以每次更新只取上次以来改动过的记录。改动超过 5,000 条，或距上次完整下载已满一个月时，改为重新下载整个压缩包，这样也会去掉上游已删除的记录。KEV 目录很小，每次整份获取。

哈希索引以 Trivy 的 java-db 打底，它每天整体重建为一个 1 GB 的文件，没有增量形式。此后每次同步只应用 Maven Central 每一两周在自己的索引中发布的新增部分（每份 10-50 MB，中央仓会保留几个月的），这样不必重下 1 GB 也能保持最新。底库本身每 180 天重新下载一次（`--hashes-every DAYS`），或在指定 `--full` 时重下。如果中央仓重置了索引，或者本地副本比中央仓仍保留的新增部分还旧，同步会停下来提示使用 `--full`，不会自行开始 1 GB 的下载。

Maven Central 限制单个地址能下载的索引量。所以同步最多每周检查一次新增部分，每应用完一份就保存进度。如果中央仓回复已达上限（HTTP 429），同步立即停止并告诉你何时再试：提前重试只会延长封禁。

连接中断时从断点续传，中途放弃的同步在下次运行时接着做。同步失败时保留已安装的副本。同一目录同一时间只能运行一个 `db sync` 或 `db remove`，第二个会直接拒绝，而不是排在一个在慢速线路上可能要下一小时的下载后面等待。

`scan --lookup` 决定如何使用数据集：

| 模式 | 行为 |
|---|---|
| `auto`（默认） | 先查已安装的数据集；其余内容以及数据集不覆盖的内容联网查询。没有数据集时等同于 `online` |
| `local` | 完全不联网：先查已安装的数据集，再查响应缓存。等同于 `--offline` |
| `online` | 忽略已安装的数据集。配合 `--offline` 时，用缓存原样重放之前的一次联网扫描 |

数据集覆盖按哈希识别 jar、漏洞匹配和 KEV 标记。有些查询仍然需要联网，或需要之前联网扫描留下的缓存：哈希索引中没有的 jar 在中央仓公布的校验和、构件本身没写明的许可证、重新构建的 jar 与其发布件的逐条比对、`--class-search`，以及随项目拷入的 JavaScript 文件。`local` 模式下，既不在数据集中、也不在缓存中的内容会被略过，并在警告中计数；因此未能识别的 jar 会注明这一点，因为联网扫描可能认得出它。

哈希索引每个文件只记一个坐标，deps.dev 会列出全部坐标；但 deps.dev 不收分类器 jar（`json-lib-2.4-jdk15.jar`），索引则收。jar 的 `pom.properties` 声明的坐标索引中没有，或索引给出的坐标与文件名对不上时，binwitness 还会查 deps.dev（或缓存）。对什么都没声明的 jar，两个来源仍可能给出同一文件的不同坐标，所以 `local` 与 `online` 两种扫描得出的组件名可能不同；`auto` 模式下先由索引回答，与 `local` 相同。

结果中记录了哪些数据集参与回答以及它们的时效（`data_sources.local`）。数据集超过七天未同步会产生警告。

每个数据集都由你的机器直接从发布方下载，并遵守发布方的条款：OSV 来自 Google 的公共存储桶（每条记录带有其来源数据库的许可证），哈希索引来自 Aqua Security 在 ghcr.io 上的 `trivy-java-db` 镜像和 Maven Central 的索引，KEV 目录来自 CISA。

## 核对其他扫描工具的结果

```
binwitness crosscheck out/binwitness.json other-tool.csv -o crosscheck.json
```

另一个工具的结果可以是带 `vulnerabilities` 部分的 CycloneDX JSON，也可以是包含 `component,version,vulnerability` 三列的 CSV。CSV 中的 `component` 写成 `group:artifact`、`npm:name` 或 purl。vulnerability 留空表示该工具识别出了这个组件，但没有发现漏洞。

只比较两个工具都识别出、且版本相同的组件，识别上的差异单独列出。binwitness 没有复现的每条发现归入以下一类：

| 类别 | 含义 |
|---|---|
| `confirmed` | GitHub 将该包的这个版本列为受影响 |
| `bundled-module` | 公告针对的是打包在该构件内部的某个模块（netty-all、shade 过的 jar） |
| `version-not-affected` | 包没错，但这个版本不在受影响范围内 |
| `same-project-other-module` | 公告针对的是同一项目的兄弟模块（把 `netty-codec-http` 的漏洞报到了 `netty-handler` 上） |
| `other-package` | 公告针对的是别的包或别的生态 |
| `unattributed` | 上游公告没有指明任何包（GitHub 的 "unreviewed"），需要人工判断 |
| `no-github-record` / `tool-specific-id` | 没有可供核对的公开记录 |

GitHub 按 CVE 搜索只能找到带有该 CVE 编号的公告，而项目自己发的公告有时只把它列为相关（netty 针对 HTTP/2 Rapid Reset 的公告，CVE-2023-44487）。所以对 GitHub 没有归到该组件名下的 Maven 发现，binwitness 还会读取该组件 groupId 下每个模块的 OSV 公告：有一条影响当前版本并引用了该 CVE 的，判 `confirmed`；引用它的是兄弟模块的，判 `same-project-other-module`。

使用 GitHub 令牌可以把 API 限额从每小时 60 次提高到 5,000 次。binwitness 依次从 `GITHUB_TOKEN`、`GH_TOKEN` 或 `gh auth token` 读取令牌。

## MCP 服务

`binwitness mcp` 通过 [Model Context Protocol](https://modelcontextprotocol.io)（stdio）让 AI 助手发起扫描、阅读结果。需要可选的 SDK（`pipx install "binwitness[mcp]"` 或 `pip install "binwitness[mcp]"`）。

```
binwitness mcp --root ~/deliveries --lookup local
```

| 选项 | 作用 |
|---|---|
| `--root DIR` | 允许助手扫描或核对其中文件的目录，可重复。路径（含符号链接）先解析，必须落在某个 root 之内。不给 root 时，只能读取按路径打开的已有结果 |
| `--lookup auto\|local\|online` | 扫描最多能用到的查询方式；单次工具调用只能要求更少，不能更多。`local` 时不发送任何内容，也不提供 `crosscheck`。默认 `auto` |
| `--allow-class-search` | 允许扫描使用会发送类名的 `--class-search`（默认关闭） |
| `--results DIR` | 扫描结果存放位置（默认 `~/.local/share/binwitness/scans`，Windows 上为 `%LOCALAPPDATA%\binwitness\scans`） |
| `--cache-dir`、`--db-dir`、`--maven-mirror`、`--maven-repo`、`--workers`、`--max-age` | 同 `scan` |

Claude Code：

```
claude mcp add binwitness -- binwitness mcp --root /home/me/deliveries --lookup local
```

Claude Desktop、Cursor 等用 `mcpServers` JSON 文件配置的客户端填同样的命令：

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

| 工具 | 作用 | 发送 |
|---|---|---|
| `start_scan` | 在单独的 `binwitness scan` 进程中扫描 root 下的文件，立即返回扫描编号；同一时间只跑一个 | 按所选查询方式，与 `scan` 相同 |
| `scan_status` | 运行中（已用时间、最后一行进度）、已完成，或失败（日志末尾） | 无 |
| `open_result` | 登记一个之前生成的 `binwitness.json` 并给出概览 | 无 |
| `list_scans` | 结果目录中的扫描，以及本次会话打开的结果 | 无 |
| `overview` | 计数、带建议的最严重发现、升级结论、许可证分类 | 无 |
| `list_components` | 每个组件一行，可按文本、严重度、生态、许可证分类或升级结论筛选；每页 20 条，最多 100 条 | 无 |
| `list_unidentified` | 未能识别的 jar 及原因 | 无 |
| `get_component` | 证据、文件、带修复版本和建议的发现、升级建议；出现位置按需给出 | 无 |
| `get_vulnerability` | 一条发现及其 OSV 记录：详情、受影响范围、参考链接 | 本地数据集没有该记录且允许联网时，向 OSV 发送公告编号 |
| `upgrade_plan` | 按严重程度排列的步骤：移除、升级、替换，或为内嵌组件更换宿主；每一步写明能消除什么、还剩什么及注意事项 | 无 |
| `crosscheck` | 拿另一个扫描工具的导出结果与某次扫描核对归类，完整报告存盘 | 与 `crosscheck` 相同；`--lookup local` 时不提供 |

每个关于结果的回答都以 `coverage` 开头：是否每次查询都成功、哪些没识别或没查、哪些查询被关闭、各数据源及其日期、做扫描的和提供服务的 binwitness 版本。它还写明结果说明不了什么：没有发现的组件，只表示截至数据日期所用数据中没有针对它的公告，不能证明它没有缺陷；也不做可达性分析。升级计划另外写明：不检查与应用的兼容性；Maven 依赖的版本常由 BOM 或父 POM 决定；npm 包可能是依赖的依赖。列表分页，文件位置只给计数，要求时才列出，以免撑满助手的上下文。

## 哪些信息会离开你的机器

binwitness 会向公共服务发送以下内容：

- jar 的 SHA-1 哈希；可能是拷入的库的 JavaScript 文件的 SHA-256 哈希（项目自己的普通源码和构建配置不查询）
- 组件坐标和版本
- CVE 编号
- 计算升级建议时，有漏洞的包的名称：发给 OSV 以取其全部公告，发给 Maven Central、`--maven-repo` 仓库或 npm registry 以取其已发布版本
- 仅在开启 `--class-search` 时：为其他方式都认不出的每个 jar 发送一个完整类名，并查询其文件名和 manifest 提示的坐标。`--first-party-group` 前缀下的类从不发送。未识别的 jar 可能是私有代码，其类名可能暴露包名，介意的话不要开启这个选项。

不会上传任何文件内容。自有 jar 不做查询。使用 `--maven-mirror` 时，对中央仓文件的请求改发给镜像，镜像的运营方能看到你查了哪些坐标。`--maven-repo` 仓库的运营方同样能看到向它查询的坐标。使用 `--lookup local` 时不发送任何内容。MCP 服务发送的只是它所运行的扫描和工具发送的内容。`binwitness db sync` 只下载公开数据集，不发送任何与你的文件有关的信息。要在不联网的机器上扫描，从联网的机器上拷贝数据集目录，需要的话再拷贝响应缓存（`--cache-dir`，默认 `~/.cache/binwitness`）。

| 服务 | 用途 |
|---|---|
| [deps.dev](https://deps.dev) | jar 哈希查坐标；许可证 |
| [Maven Central](https://central.sonatype.com) | 哈希搜索兜底；发布的校验和；POM 中的许可证；`--class-search`；升级建议的版本列表；`crosscheck` 查 groupId 下的模块 |
| 用 `--maven-repo` 指定的仓库 | 中央仓没有的版本的校验和、jar 目录、POM 许可证和版本列表 |
| [OSV.dev](https://osv.dev) | 漏洞（GitHub 安全公告及其他来源）；升级建议所需的有漏洞的包的全部公告 |
| [npm registry](https://www.npmjs.com) | 升级建议所需的有漏洞的 npm 包的已发布版本；JavaScript 文件匹配到的包的已发布版本 |
| [jsDelivr](https://www.jsdelivr.com) | JavaScript 文件哈希；匹配版本前后相邻版本的文件列表 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已知被利用标记 |
| [OSV 数据存储桶](https://google.github.io/osv.dev/data/) | OSV 数据集的 `db sync` |
| [ghcr.io](https://github.com/aquasecurity/trivy-java-db) | Maven Central 哈希索引的 `db sync` |
| [Maven Central 索引](https://repo1.maven.org/maven2/.index/) | `db sync`：哈希索引的每周新增 |
| [GitHub 安全公告](https://github.com/advisories) | 仅 `crosscheck` |

## 局限

以下限制是有意为之，依赖结果之前请先读一遍：

- **本地匹配使用 binwitness 自己的版本排序**。本地数据集中的公告版本范围由 binwitness 实现的 Maven 和 semver 排序判断，在线 API 用的是 OSV 自己的实现。常规版本号上两者一致，不常见的版本字符串可能比较结果不同。
- **漏洞覆盖范围就是 OSV 的覆盖范围**。没有指明包的公告（GitHub "unreviewed"、只有 CPE 的 NVD 记录）无法匹配到组件。不查询厂商私有漏洞库和各国的国家漏洞库。漏洞数应视为下限。拿 `crosscheck` 去核对商业工具的输出，是了解这类数据库能补充多少的实用办法。
- **识别需要已发布的构件或声明**。私有构建、分叉版本，以及不带 `pom.properties` 的改包名副本会保持未识别，除非同一交付物里还有一份已识别的副本（或者 `--class-search` 找到了它）。只在其他仓库发布的版本（里程碑版、厂商自己的构建）要用 `--maven-repo` 才认得出。每个未识别的 jar 都写明原因，并给出 manifest 或文件名提示的身份（`hint`，未经核实）。shade 时没带上 `pom.properties` 的类认不出；binwitness 不做字节码或源码指纹。内容比对比较的是 CRC-32，能发现重新构建和一般修改，防不了蓄意伪造的碰撞。只含 manifest、许可证和 notice 的 jar（Spring Boot starter）在不同构件之间看起来都一样，从不按内容匹配，报告为不含代码。分类器 jar（`-linux-x86_64`）只与主构件比较。
- **升级建议只针对公告，不涉及兼容性**。它说明哪个已发布版本不在 OSV 中该包公告的影响范围内。应用换上它能否构建和运行、版本是否由 BOM、父 POM 或其他包决定、受影响的代码是否可达，都不做评估。读取版本列表之后才发布的版本不在考虑之内。
- **前端打包产物是不透明的**。webpack 或 rollup 合并进 chunk 的代码无法按哈希匹配。请把锁文件，或构建时用的 `node_modules`，随打包产物一起交付。文件头注释只能覆盖一部分。认出的打包产物单独计数（`bundled_scripts`），不当作未知的库。
- **生态：Java（Maven）和 JavaScript（npm）**。操作系统软件包、Python、Go、.NET 和原生库不在范围内；镜像的操作系统层请用 Trivy 或 Syft。这些生态的依赖文件会在警告中点名。JDK/JRE 运行时 jar 会跳过。
- **非常规许可证需要人工判断**。非标准许可证和自相矛盾的声明归为 `unknown`。并列多个许可证而没有写成 SPDX 表达式的，按任选其一理解。
- **扫描速度取决于网络**。冷缓存扫描几乎全部时间都在等待查询：含 190 个 jar 的 war 约需三分钟，上千个 jar 的交付物约需一刻钟。10 秒内建不起来的连接、卡住 30 秒的请求（包括域名解析）都会放弃并重试。`--class-search` 依赖的 Maven Central 搜索服务会把部分请求压上最长一分钟才回答，binwitness 对它最多同时发两个请求，8 秒没有回答就重发。用缓存重跑只需几秒，为一个交付物查过的常见库，扫下一个交付物时已在缓存中。
- **在线服务可能宕机或限流**。查询失败会退避重试约一分钟，之后记为警告，扫描不会因此整体失败。此时结果标为 `INCOMPLETE`，`--fail-on` 以状态码 4 而不是 0 退出。

## 开发

```
pip install -e ".[test,mcp]"
pytest
```

测试自己构造压缩包，网络调用由预设的响应回答，从不访问互联网。没装 SDK 时 MCP 测试自动跳过；其中一个测试通过 stdio 启动 `binwitness mcp` 并经由它跑一次扫描。

## 许可证

Apache-2.0
