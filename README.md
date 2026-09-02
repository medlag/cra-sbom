# cra-sbom

**CRA readiness for a .NET solution. One Python file, nothing to install.**

From **11 September 2026**, manufacturers placing products with digital elements on the
EU market must report actively exploited vulnerabilities within 24 hours — including in
products already shipped. From **11 December 2027**, conformity requires a machine-readable
SBOM covering at least top-level dependencies.

You cannot report on what you have not inventoried. This produces the inventory.

```bash
dotnet restore YourSolution.sln
python cra_sbom.py ./src --out ./artifacts
```

Two files come out:

| File | What it is |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 SBOM — attach it to your release |
| `cra-readiness.md` | What you can and cannot answer today |

## Why not just use the CycloneDX tool

You can, and for many teams you should. This exists for the case where you want an
answer in the next ten minutes without adding a global tool, a CI package, or a vendor:

- **No install.** Standard-library Python. No `dotnet tool install`, no NuGet package.
- **No build.** It reads the `obj/project.assets.json` files `dotnet restore` already
  wrote, which means it sees the *resolved* graph — the versions that actually ship,
  not the ranges you asked for.
- **Test dependencies are separated.** xUnit does not ship to your customers, so it
  is scoped `optional` in the SBOM and excluded from the CRA counts.
- **It reports, not just lists.** The version conflicts are the finding.
- **Provenance is version-correct.** A parent is recorded against the version actually
  resolved in that target — not against every version of that package in the solution.

## Tests

```bash
python -m unittest -v
```

18 tests, standard library only, no pytest. They cover the things that are easy to get
wrong: version-correct provenance, transitively-pinned packages not counting as direct,
project references not appearing as parent packages, and test projects staying out of
the shipped set.

## What the report tells you

Run against a real 136-project .NET 9 modular monolith:

```
| Components in shipped product | 438   |
| Declared directly in a csproj | 137   |
| Pulled in transitively        | 301   |
| Amplification                 | 3.2x  |

47 packages resolve to more than one version
```

That last line is the point. An advisory names one version. If your solution ships
four versions of `Microsoft.Identity.Client` at once, a 24-hour report means checking
four.

The interesting part of that run: the solution **already had** central package
management with transitive pinning enabled and 158 versions pinned. Every one of the
47 conflicts was a package simply missing from `Directory.Packages.props` — transitive
pinning only pins what you list. "We use CPM" is not the same as "we have no version
drift", and the report names the exact gap.

Provenance is reported for anything with an advisory: whether you declare it yourself
(bump it) or whether something else drags it in (bump the parent, or pin deliberately).

## Vulnerability matching

Off by default:

```bash
python cra_sbom.py ./src --out ./artifacts --check-vulns
```

Queries [OSV.dev](https://osv.dev) in batches and adds an advisory section to the report.
It is off by default because it sends package names and versions to a third party — all
public NuGet identifiers, but the combination describes your stack. Your call, made
deliberately.

An advisory is not automatically a CRA report. The September 2026 obligation triggers on
*actively exploited* vulnerabilities. Treat the output as a triage queue.

## In CI

Copy [`examples/sbom.yml`](examples/sbom.yml) into your own `.github/workflows/`. It
generates the SBOM on every release and attaches it to the release, so the inventory
always matches the binary you shipped — the pairing auditors care about.

Requires Python 3.10 or newer. No packages.

## Scope, honestly

- Whether **your** product is in CRA scope is a legal question. A SaaS backend may sit
  outside "products with digital elements" depending on how it is delivered. This tool
  does not decide that, and neither should a blog post.
- It covers NuGet packages. Native dependencies, container base images, JavaScript in a
  bundled front-end, and vendored source are **not** included — and the CRA does not
  care that they were inconvenient.
- Project references are resolved as part of your own product, not as components.
- The SBOM has no license metadata. `project.assets.json` does not carry it, and
  guessing it would be worse than omitting it.

## Licence

MIT.
