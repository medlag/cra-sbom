"""
CRA readiness for a .NET solution, with no tooling to install.

Reads every obj/project.assets.json NuGet already produced during restore and emits:
  1. a CycloneDX 1.6 SBOM  - the machine-readable inventory the CRA requires from 11 Dec 2027
  2. a readiness report    - what you must be able to answer within 24h from 11 Sep 2026

Usage:  python cra_sbom.py <solution-root> [--out DIR]
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

ASSETS = "project.assets.json"
SKIP_DIRS = {".git", ".claude", ".vs", "node_modules", "TestResults"}

TEST_MARKERS = (
    "xunit", "nunit", "mstest", "moq", "nsubstitute", "fluentassertions",
    "bogus", "coverlet", "microsoft.net.test.sdk", "testcontainers",
    "verify", "shouldly", "autofixture", "respawn",
)


def find_assets(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if ASSETS in filenames and os.path.basename(dirpath) == "obj":
            yield os.path.join(dirpath, ASSETS)


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def project_name(doc, path):
    restore = doc.get("project", {}).get("restore", {})
    name = restore.get("projectName")
    if name:
        return name
    return os.path.basename(os.path.dirname(os.path.dirname(path)))


def direct_names(doc):
    """Names declared in the csproj itself, versions stripped.

    centralTransitiveDependencyGroups is deliberately excluded: under central
    package management those are transitive packages that happen to be pinned,
    which is the opposite of a direct declaration.
    """
    out = set()
    for deps in doc.get("projectFileDependencyGroups", {}).values():
        for entry in deps:
            out.add(re.split(r"[\s><=]", entry.strip(), maxsplit=1)[0].lower())
    return out


def central_management(root):
    """Locate Directory.Packages.props and report what it already pins."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "Directory.Packages.props" in filenames:
            path = os.path.join(dirpath, "Directory.Packages.props")
            try:
                text = open(path, encoding="utf-8-sig").read()
            except OSError:
                continue
            return {
                "path": path,
                "enabled": "true" in re.search(
                    r"<ManagePackageVersionsCentrally>(.*?)<", text, re.I | re.S
                ).group(1).lower() if re.search(
                    r"<ManagePackageVersionsCentrally>(.*?)<", text, re.I | re.S
                ) else False,
                "transitive_pinning": bool(
                    re.search(r"<CentralPackageTransitivePinningEnabled>\s*true", text, re.I)
                ),
                "pinned": set(re.findall(r'PackageVersion\s+Include="([^"]+)"', text)),
            }
    return None


def is_test_project(name, directs):
    low = name.lower()
    if low.endswith(("tests", "test", ".unittests", ".integrationtests")):
        return True
    return any(any(m in d for m in TEST_MARKERS) for d in directs)


def collect(root):
    packages = {}            # (name, version) -> record
    per_project = {}
    files = list(find_assets(root))

    for path in files:
        try:
            doc = load(path)
        except (ValueError, OSError) as exc:
            print(f"  ! skipped {path}: {exc}", file=sys.stderr)
            continue

        name = project_name(doc, path)
        directs = direct_names(doc)
        test = is_test_project(name, directs)
        libs = doc.get("libraries", {})

        resolved = 0
        for key, meta in libs.items():
            if meta.get("type") != "package":
                continue
            pkg, _, version = key.partition("/")
            resolved += 1
            rec = packages.setdefault(
                (pkg, version),
                {
                    "name": pkg,
                    "version": version,
                    "sha512": meta.get("sha512"),
                    "direct": False,
                    "shipped": False,
                    "projects": set(),
                    "parents": set(),
                    "declared_in": set(),
                },
            )
            rec["projects"].add(name)
            if pkg.lower() in directs:
                rec["direct"] = True
                rec["declared_in"].add(name)
            if not test:
                rec["shipped"] = True

        for target in doc.get("targets", {}).values():
            for key, meta in target.items():
                parent = key.partition("/")[0]
                for dep in (meta.get("dependencies") or {}):
                    for (pkg, version) in packages:
                        if pkg == dep:
                            packages[(pkg, version)]["parents"].add(parent)

        per_project[name] = {
            "direct": len(directs),
            "resolved": resolved,
            "test": test,
            "path": path,
        }

    return packages, per_project, files


def purl(name, version):
    return f"pkg:nuget/{name}@{version}"


def query_osv(packages, batch=500):
    """Match shipped components against OSV.dev.

    Off by default: this sends package names and versions to a third party.
    They are all public NuGet identifiers, but the combination describes your stack.
    """
    import urllib.request

    shipped = sorted(k for k, v in packages.items() if v["shipped"])
    findings = {}
    for start in range(0, len(shipped), batch):
        chunk = shipped[start:start + batch]
        payload = {
            "queries": [
                {"package": {"name": n, "ecosystem": "NuGet"}, "version": v}
                for n, v in chunk
            ]
        }
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            results = json.load(resp).get("results", [])
        for key, result in zip(chunk, results):
            vulns = result.get("vulns") or []
            if vulns:
                findings[key] = [v["id"] for v in vulns]
        print(f"  checked {min(start + batch, len(shipped))}/{len(shipped)}")
    return findings


def build_cyclonedx(packages, root):
    serial = hashlib.sha256(os.path.abspath(root).encode()).hexdigest()[:32]
    components = []
    for (name, version), rec in sorted(packages.items()):
        comp = {
            "type": "library",
            "bom-ref": purl(name, version),
            "name": name,
            "version": version,
            "purl": purl(name, version),
            "scope": "required" if rec["shipped"] else "optional",
        }
        if rec["sha512"]:
            comp["hashes"] = [{"alg": "SHA-512", "content": rec["sha512"]}]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "component": {
                "type": "application",
                "bom-ref": "root-application",
                "name": os.path.basename(os.path.abspath(root)) or "application",
            },
            "tools": {"components": [{"type": "application", "name": "cra_sbom.py"}]},
        },
        "components": components,
    }


def report(packages, per_project, files, root, vulns=None, cpm=None):
    shipped = {k: v for k, v in packages.items() if v["shipped"]}
    direct_shipped = {k: v for k, v in shipped.items() if v["direct"]}

    by_name = defaultdict(set)
    for (name, version), rec in shipped.items():
        by_name[name].add(version)
    conflicts = {n: sorted(v) for n, v in by_name.items() if len(v) > 1}

    unpinned = [k for k, v in shipped.items() if not v["sha512"]]
    prerelease = sorted({k[0] + " " + k[1] for k in shipped if "-" in k[1]})

    projects_shipped = [n for n, m in per_project.items() if not m["test"]]

    lines = []
    add = lines.append
    add(f"# CRA readiness - {os.path.basename(os.path.abspath(root))}")
    add("")
    add(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"from {len(files)} restore graphs. No external tooling.")
    add("")
    add("## The numbers")
    add("")
    add("| | Count |")
    add("|---|---|")
    add(f"| Projects analysed | {len(per_project)} |")
    add(f"| Shipping projects (non-test) | {len(projects_shipped)} |")
    add(f"| **Components in shipped product** | **{len(shipped)}** |")
    add(f"| Declared directly in a csproj | {len(direct_shipped)} |")
    add(f"| Pulled in transitively | {len(shipped) - len(direct_shipped)} |")
    add(f"| Test-only components (out of CRA scope) | {len(packages) - len(shipped)} |")
    if direct_shipped:
        add(f"| Amplification factor | {len(shipped) / len(direct_shipped):.1f}x |")
    add("")
    add("The gap between rows 4 and 5 is the whole point. The CRA asks what is *in* the")
    add("product, not what you chose to reference.")
    add("")
    add("## Findings")
    add("")

    if conflicts:
        add(f"### {len(conflicts)} packages resolve to more than one version")
        add("")
        add("A vulnerability advisory names one version. If your solution ships several,")
        add("a 24-hour report means checking each. These are the ones to unify first -")
        add("central package management (`Directory.Packages.props`) removes the class of problem.")
        add("")
        for name in sorted(conflicts)[:25]:
            add(f"- `{name}` - {', '.join(conflicts[name])}")
        if len(conflicts) > 25:
            add(f"- ... and {len(conflicts) - 25} more")
        add("")
    else:
        add("### No version conflicts")
        add("")
        add("Every shipped package resolves to a single version. Good starting position.")
        add("")

    if prerelease:
        add(f"### {len(prerelease)} pre-release versions in shipped code")
        add("")
        for item in prerelease[:15]:
            add(f"- `{item}`")
        if len(prerelease) > 15:
            add(f"- ... and {len(prerelease) - 15} more")
        add("")

    if unpinned:
        add(f"### {len(unpinned)} components without an integrity hash")
        add("")
        for name, version in sorted(unpinned)[:10]:
            add(f"- `{name}` {version}")
        add("")

    if vulns is not None:
        if vulns:
            add(f"### {len(vulns)} shipped components have known advisories")
            add("")
            add("Matched against OSV.dev. An advisory is not automatically a CRA report -")
            add("the 11 September obligation triggers on *actively exploited* vulnerabilities.")
            add("Treat this as the triage queue, not the incident list.")
            add("")
            for (name, version), ids in sorted(vulns.items()):
                rec = packages[(name, version)]
                add(f"**`{name}` {version}** - {len(ids)} advisor"
                    + ("y" if len(ids) == 1 else "ies")
                    + f": {', '.join(ids[:5])}"
                    + (f" (+{len(ids) - 5} more)" if len(ids) > 5 else ""))
                declared = sorted(rec["declared_in"])
                if declared:
                    shown = ", ".join(f"`{d}`" for d in declared[:6])
                    more = f" (+{len(declared) - 6})" if len(declared) > 6 else ""
                    add(f"  - Declared directly in {len(declared)} project(s): {shown}{more}"
                        " - **you control this version, bump it**")
                parents = sorted(rec["parents"] - {name})
                if parents:
                    shown = ", ".join(f"`{x}`" for x in parents[:6])
                    more = f" (+{len(parents) - 6})" if len(parents) > 6 else ""
                    add(f"  - Pulled in by {shown}{more}"
                        + ("" if declared else " - bump the parent, or pin deliberately"))
                add(f"  - Reaches {len(rec['projects'])} project(s)")
                add("")
            add("")
        else:
            add("### No known advisories")
            add("")
            add("All shipped components came back clean from OSV.dev at generation time.")
            add("That is a snapshot, not a state - it is why this has to run on a schedule.")
            add("")

    add("## What each date actually asks of you")
    add("")
    add("**11 September 2026** - report actively exploited vulnerabilities within 24 hours,")
    add("including in products already shipped. You cannot do that without this inventory,")
    add(f"and yours has {len(shipped)} entries to watch.")
    add("")
    add("**11 December 2027** - CE marking plus a machine-readable SBOM covering at least")
    add("top-level dependencies. `sbom.cdx.json` beside this file is that artefact, in")
    add("CycloneDX 1.6, ready to attach to a release.")
    add("")
    add("## Next steps")
    add("")
    add("1. Attach `sbom.cdx.json` to every release build so the inventory matches the artefact.")
    step = 2
    if conflicts:
        if cpm and cpm["enabled"]:
            unpinned_conflicts = sorted(set(conflicts) - cpm["pinned"])
            add(f"{step}. Central package management is already on"
                + (" with transitive pinning" if cpm["transitive_pinning"] else "")
                + f" ({len(cpm['pinned'])} versions pinned), so the fix is narrow: "
                + f"**{len(unpinned_conflicts)} of the {len(conflicts)} conflicting packages "
                "are missing from `Directory.Packages.props`.** Add them and the conflict "
                "resolves at the next restore.")
            if unpinned_conflicts:
                add("")
                for name in unpinned_conflicts[:12]:
                    add(f"   - `{name}` - {', '.join(conflicts[name])}")
                if len(unpinned_conflicts) > 12:
                    add(f"   - ... and {len(unpinned_conflicts) - 12} more")
                add("")
        else:
            add(f"{step}. Adopt central package management to collapse the version conflicts above.")
        step += 1
    add(f"{step}. Feed the purls to an advisory source (OSV, GitHub Advisory) on a schedule.")
    add(f"{step + 1}. Write the 24-hour disclosure runbook - who decides, who files, to which CSIRT.")
    add("")
    add("Verify scope against the CRA text before relying on this. A SaaS backend may sit")
    add("outside 'products with digital elements' depending on how it is delivered - that is")
    add("a legal question, not a tooling one.")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out", default=".")
    ap.add_argument("--check-vulns", action="store_true",
                    help="query OSV.dev; sends package names and versions to a third party")
    args = ap.parse_args()

    print(f"Scanning {args.root} ...")
    packages, per_project, files = collect(args.root)
    if not files:
        print("No project.assets.json found. Run 'dotnet restore' first.", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    sbom_path = os.path.join(args.out, "sbom.cdx.json")
    report_path = os.path.join(args.out, "cra-readiness.md")

    with open(sbom_path, "w", encoding="utf-8") as fh:
        json.dump(build_cyclonedx(packages, args.root), fh, indent=2)
    vulns = None
    if args.check_vulns:
        print("Querying OSV.dev ...")
        vulns = query_osv(packages)

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report(packages, per_project, files, args.root, vulns, central_management(args.root)))

    shipped = sum(1 for v in packages.values() if v["shipped"])
    print(f"  {len(files)} restore graphs, {len(packages)} components ({shipped} shipped)")
    print(f"  -> {sbom_path}")
    print(f"  -> {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
