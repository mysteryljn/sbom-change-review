# sbom-change-review

**Catch unexpected component and license changes before a release ships.** Compare existing CycloneDX or SPDX inventories and produce a reviewable, offline report with explicit release-policy exit codes.

A gateway release changes `gateway-core` from 1.2.0/MIT to 1.3.0/`MIT OR GPL-3.0-only`, adds a codec with an unknown license, and contains two versions of a transport library. This tool shows those changes without guessing which transport version replaced which.

[中文说明](README.zh-CN.md) · [Synthetic examples](sbom_change_review/fixtures/README.md)

## Install and try

Python 3.10 or newer; no runtime dependencies, network calls or credentials.

```sh
python -m pip install .
python -m sbom_change_review demo --output report.html
sbom-change-review --version
```

Open `report.html` in a browser. It includes its own styles and filtering script; no CDN is contacted. The demo uses packaged, fictional fixtures and works from any working directory after installation.

```sh
sbom-change-review compare baseline.cdx.json release.spdx.json --output release.html
sbom-change-review compare old.json new.json --deny-license GPL-3.0-only --deny-new --deny-unknown-license --output review.json
sbom-change-review compare old.json new.json --format markdown --output review.md
```

Formats are inferred from `.html`, `.htm`, `.md`; other extensions and stdout use JSON. `--format` overrides this. Outputs are written atomically; input files cannot be overwritten.

## Identity and change semantics

- Supports the component inventory subset of **CycloneDX JSON 1.5/1.6** and **SPDX JSON 2.3**, including nested CycloneDX components. The target in `metadata.component` is not counted as a dependency. SPDX `packages` are all included.
- Component identity uses a purl with its version removed. Namespace, qualifiers and subpath remain significant. Where no purl exists, the exact `(group, name)` pair is used. Local `bom-ref`/`SPDXID` values are evidence only, never cross-document identity.
- A one-to-one match produces exact version/license changes. Multiple versions or duplicate records are retained and reported as **ambiguous** when their inventory changes. The full before/after arrays remain available in JSON.
- Versions are compared as exact strings, without claiming upgrades or downgrades across incompatible version schemes. Missing versions remain unknown. Purl and explicit version disagreements are rejected.
- SPDX `licenseConcluded` takes precedence; absent/`NOASSERTION` conclusions fall back to `licenseDeclared`. License expressions are retained, not legally interpreted.

## Release policies and exit codes

| Option | Gate |
|---|---|
| `--deny-new` | Newly introduced identities |
| `--deny-license ID` (repeatable) | Exact ID/name or identifier token in an expression, anywhere in current inventory |
| `--deny-unknown-license` | Missing, `NOASSERTION`, `NONE`, or `UNKNOWN` licenses |
| `--deny-ambiguous` | Changed identities with multiple candidate records |

`0` means the selected policies pass; `1` means a policy fails and a report is still produced; `2` means invalid input or report I/O failure. Without policy flags, changes alone do not fail CI. In `MIT OR GPL-3.0-only`, denying GPL conservatively flags the expression for review even though it includes an alternative. This is not a license-expression solver.

```yaml
- run: python -m pip install .
- run: sbom-change-review compare baseline.json current.json --deny-unknown-license --output sbom-review.html
```

## Why another SBOM tool?

[CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) already provides BOM diff, merge and conversion. This project focuses on **release-review policies, transparent ambiguous identity handling and a standalone report**. It consumes scanner output; it does not generate SBOMs, resolve dependencies, query vulnerability databases or establish automotive compliance.

Limitations: supported field subset rather than full schema validation; no XML/protobuf, relationship-graph diff, signature verification, vulnerability matching, ecosystem-specific name canonicalization, or complete purl specification validation. Nonstandard vendor fields are not compared. License spelling and expressions are compared exactly; policy tokens are a conservative review aid. A maliciously huge document can exceed available memory. Input and output files are trusted local paths.

## Develop

```sh
python -m unittest discover -s tests -v
python -m pip wheel . --no-deps --wheel-dir dist
```

Tests cover real JSON fixtures, cross-format identity, duplicate/multi-version inventories, nested components, unknown licenses, expression policies, HTML escaping and CLI failures. See [fixture provenance](sbom_change_review/fixtures/README.md). Contributions with reproducible, sanitized exporter fixtures are welcome. MIT license.
