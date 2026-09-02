"""CRA readiness and CycloneDX SBOM for a .NET solution.

Reads the obj/project.assets.json graphs `dotnet restore` already produced and emits
a CycloneDX 1.6 SBOM plus a readiness report.

Usage:  python cra_sbom.py <root> [--out DIR] [--check-vulns]
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

ASSETS_FILE = "project.assets.json"
PROPS_FILE = "Directory.Packages.props"
SKIP_DIRS = frozenset({".git", ".claude", ".vs", "node_modules", "TestResults", "bin"})

TEST_SDK = "microsoft.net.test.sdk"
TEST_RUNNERS = frozenset({"xunit", "xunit.v3", "nunit", "mstest.testframework"})
TEST_NAME_SUFFIXES = ("tests", ".test", ".unittests", ".integrationtests")

OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 500
OSV_TIMEOUT_SECONDS = 60

MAX_LISTED_CONFLICTS = 25
MAX_LISTED_UNPINNED = 12
MAX_LISTED_PRERELEASE = 15
MAX_LISTED_PROJECTS = 6
MAX_LISTED_ADVISORY_IDS = 5


@dataclass
class Component:
    name: str
    version: str
    sha512: str | None = None
    shipped: bool = False
    declared_in: set[str] = field(default_factory=set)
    parents: set[str] = field(default_factory=set)
    projects: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)

    @property
    def purl(self) -> str:
        return f"pkg:nuget/{self.name}@{self.version}"

    @property
    def is_direct(self) -> bool:
        return bool(self.declared_in)


@dataclass
class Inventory:
    components: dict[tuple[str, str], Component] = field(default_factory=dict)
    test_projects: set[str] = field(default_factory=set)
    all_projects: set[str] = field(default_factory=set)
    graph_count: int = 0

    def shipped(self) -> list[Component]:
        return [c for c in self.components.values() if c.shipped]

    def conflicts(self) -> dict[str, list[str]]:
        versions = defaultdict(set)
        for component in self.shipped():
            versions[component.name].add(component.version)
        return {n: sorted(v) for n, v in versions.items() if len(v) > 1}


@dataclass
class CentralPackages:
    path: str
    enabled: bool
    transitive_pinning: bool
    pinned: set[str]


def find_assets(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if ASSETS_FILE in filenames and os.path.basename(dirpath) == "obj":
            yield os.path.join(dirpath, ASSETS_FILE)


def read_json(path):
    with open(path, encoding="utf-8-sig") as handle:
        return json.load(handle)


def project_name(doc, path):
    declared = doc.get("project", {}).get("restore", {}).get("projectName")
    return declared or os.path.basename(os.path.dirname(os.path.dirname(path)))


def declared_names(doc):
    """Package ids written in the csproj, lowercased.

    centralTransitiveDependencyGroups is excluded on purpose: under central package
    management those are transitive packages that happen to be pinned, which is the
    opposite of a direct declaration.
    """
    names = set()
    for group in doc.get("projectFileDependencyGroups", {}).values():
        for entry in group:
            names.add(re.split(r"[\s><=]", entry.strip(), maxsplit=1)[0].lower())
    return names


def is_test_project(name, declared):
    if TEST_SDK in declared or declared & TEST_RUNNERS:
        return True
    return name.lower().endswith(TEST_NAME_SUFFIXES)


def _package_entries(doc):
    for key, meta in doc.get("libraries", {}).items():
        if meta.get("type") == "package":
            name, _, version = key.partition("/")
            yield name, version, meta


def _record_parents(doc, inventory):
    """Attribute each dependency edge to the resolved version inside its own target."""
    for target in doc.get("targets", {}).values():
        resolved = {}
        for key in target:
            name, _, version = key.partition("/")
            resolved[name] = version
        for key, meta in target.items():
            if meta.get("type") != "package":
                continue
            parent = key.partition("/")[0]
            for dependency in meta.get("dependencies") or {}:
                version = resolved.get(dependency)
                component = inventory.components.get((dependency, version))
                if component is not None and parent != dependency:
                    component.parents.add(parent)


def _absorb(doc, path, inventory):
    name = project_name(doc, path)
    declared = declared_names(doc)
    test = is_test_project(name, declared)

    inventory.all_projects.add(name)
    if test:
        inventory.test_projects.add(name)

    for package, version, meta in _package_entries(doc):
        component = inventory.components.setdefault(
            (package, version), Component(package, version, meta.get("sha512"))
        )
        component.projects.add(name)
        if package.lower() in declared:
            component.declared_in.add(name)
        if not test:
            component.shipped = True

    _record_parents(doc, inventory)


def scan(root):
    inventory = Inventory()
    for path in find_assets(root):
        try:
            doc = read_json(path)
        except (ValueError, OSError) as exc:
            print(f"  ! skipped {path}: {exc}", file=sys.stderr)
            continue
        inventory.graph_count += 1
        _absorb(doc, path, inventory)
    return inventory


def read_central_packages(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if PROPS_FILE not in filenames:
            continue
        path = os.path.join(dirpath, PROPS_FILE)
        try:
            with open(path, encoding="utf-8-sig") as handle:
                text = handle.read()
        except OSError:
            continue
        return CentralPackages(
            path=path,
            enabled=bool(re.search(r"<ManagePackageVersionsCentrally>\s*true", text, re.I)),
            transitive_pinning=bool(
                re.search(r"<CentralPackageTransitivePinningEnabled>\s*true", text, re.I)
            ),
            pinned=set(re.findall(r'PackageVersion\s+Include="([^"]+)"', text)),
        )
    return None


def query_osv(components, batch_size=OSV_BATCH_SIZE):
    """Match components against OSV.dev. Sends package ids to a third party."""
    keys = sorted(c.key for c in components)
    findings = {}
    for start in range(0, len(keys), batch_size):
        chunk = keys[start:start + batch_size]
        findings.update(_query_osv_batch(chunk))
        print(f"  checked {min(start + batch_size, len(keys))}/{len(keys)}")
    return findings


def _query_osv_batch(chunk):
    payload = {
        "queries": [
            {"package": {"name": name, "ecosystem": "NuGet"}, "version": version}
            for name, version in chunk
        ]
    }
    request = urllib.request.Request(
        OSV_ENDPOINT,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:
            results = json.load(response).get("results", [])
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError(f"OSV query failed: {exc}") from exc

    found = {}
    for key, result in zip(chunk, results):
        ids = [v["id"] for v in result.get("vulns") or []]
        if ids:
            found[key] = ids
    return found


def to_cyclonedx(inventory, root):
    digest = hashlib.sha256(os.path.abspath(root).encode()).hexdigest()[:32]
    serial = "-".join([digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "component": {
                "type": "application",
                "bom-ref": "root-application",
                "name": os.path.basename(os.path.abspath(root)) or "application",
            },
            "tools": {"components": [{"type": "application", "name": "cra-sbom"}]},
        },
        "components": [_component_json(c) for _, c in sorted(inventory.components.items())],
    }


def _component_json(component):
    entry = {
        "type": "library",
        "bom-ref": component.purl,
        "name": component.name,
        "version": component.version,
        "purl": component.purl,
        "scope": "required" if component.shipped else "optional",
    }
    if component.sha512:
        entry["hashes"] = [{"alg": "SHA-512", "content": component.sha512}]
    return entry


def _truncated(items, limit, render):
    lines = [render(item) for item in items[:limit]]
    if len(items) > limit:
        lines.append(f"- ... and {len(items) - limit} more")
    return lines


def _numbers_section(inventory, root):
    shipped = inventory.shipped()
    direct = [c for c in shipped if c.is_direct]
    shipping_projects = inventory.all_projects - inventory.test_projects
    lines = [
        f"# CRA readiness - {os.path.basename(os.path.abspath(root))}",
        "",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} from "
        f"{inventory.graph_count} restore graphs. No external tooling.",
        "",
        "## The numbers",
        "",
        "| | Count |",
        "|---|---|",
        f"| Projects analysed | {len(inventory.all_projects)} |",
        f"| Shipping projects (non-test) | {len(shipping_projects)} |",
        f"| **Components in shipped product** | **{len(shipped)}** |",
        f"| Declared directly in a csproj | {len(direct)} |",
        f"| Pulled in transitively | {len(shipped) - len(direct)} |",
        f"| Test-only components (out of CRA scope) | {len(inventory.components) - len(shipped)} |",
    ]
    if direct:
        lines.append(f"| Amplification factor | {len(shipped) / len(direct):.1f}x |")
    lines += ["", "The CRA asks what is *in* the product, not what you chose to reference.", ""]
    return lines


def _conflicts_section(conflicts):
    if not conflicts:
        return ["## Findings", "", "### No version conflicts", "",
                "Every shipped package resolves to a single version.", ""]
    lines = [
        "## Findings", "",
        f"### {len(conflicts)} packages resolve to more than one version", "",
        "An advisory names one version. If your solution ships several, a 24-hour",
        "report means checking each.", "",
    ]
    lines += _truncated(
        sorted(conflicts), MAX_LISTED_CONFLICTS,
        lambda n: f"- `{n}` - {', '.join(conflicts[n])}",
    )
    return lines + [""]


def _prerelease_section(shipped):
    items = sorted(f"{c.name} {c.version}" for c in shipped if "-" in c.version)
    if not items:
        return []
    lines = [f"### {len(items)} pre-release versions in shipped code", ""]
    lines += _truncated(items, MAX_LISTED_PRERELEASE, lambda i: f"- `{i}`")
    return lines + [""]


def _provenance_lines(component):
    lines = []
    declared = sorted(component.declared_in)
    if declared:
        lines.append(
            f"  - Declared directly in {len(declared)} project(s): "
            f"{_names(declared)} - **you control this version, bump it**"
        )
    parents = sorted(component.parents)
    if parents:
        hint = "" if declared else " - bump the parent, or pin deliberately"
        lines.append(f"  - Pulled in by {_names(parents)}{hint}")
    lines.append(f"  - Reaches {len(component.projects)} project(s)")
    return lines


def _names(values):
    shown = ", ".join(f"`{v}`" for v in values[:MAX_LISTED_PROJECTS])
    extra = len(values) - MAX_LISTED_PROJECTS
    return shown + (f" (+{extra})" if extra > 0 else "")


def _advisories_section(inventory, vulns):
    if vulns is None:
        return []
    if not vulns:
        return ["### No known advisories", "",
                "All shipped components were clean at generation time. That is a",
                "snapshot, not a state - which is why this runs on a schedule.", ""]
    lines = [
        f"### {len(vulns)} shipped components have known advisories", "",
        "Matched against OSV.dev. An advisory is not automatically a CRA report - the",
        "11 September obligation triggers on *actively exploited* vulnerabilities.", "",
    ]
    for key, ids in sorted(vulns.items()):
        shown = ", ".join(ids[:MAX_LISTED_ADVISORY_IDS])
        extra = len(ids) - MAX_LISTED_ADVISORY_IDS
        suffix = f" (+{extra} more)" if extra > 0 else ""
        plural = "y" if len(ids) == 1 else "ies"
        lines.append(f"**`{key[0]}` {key[1]}** - {len(ids)} advisor{plural}: {shown}{suffix}")
        lines += _provenance_lines(inventory.components[key])
        lines.append("")
    return lines


def _dates_section(shipped_count):
    return [
        "## What each date asks of you", "",
        "**11 September 2026** - report actively exploited vulnerabilities within 24",
        "hours, including in products already shipped. You cannot do that without this",
        f"inventory, and yours has {shipped_count} entries to watch.", "",
        "**11 December 2027** - CE marking plus a machine-readable SBOM covering at",
        "least top-level dependencies. `sbom.cdx.json` is that artefact.", "",
    ]


def _next_steps_section(conflicts, central):
    lines = ["## Next steps", "",
             "1. Attach `sbom.cdx.json` to every release so the inventory matches the binary."]
    step = 2
    if conflicts:
        lines += _conflict_remedy(conflicts, central, step)
        step += 1
    lines += [
        f"{step}. Feed the purls to an advisory source on a schedule.",
        f"{step + 1}. Write the 24-hour disclosure runbook - who decides, who files, to which CSIRT.",
        "",
        "Whether your product is in CRA scope is a legal question, not a tooling one.",
    ]
    return lines


def _conflict_remedy(conflicts, central, step):
    if not (central and central.enabled):
        return [f"{step}. Adopt central package management to collapse the conflicts above."]
    missing = sorted(set(conflicts) - central.pinned)
    pinning = " with transitive pinning" if central.transitive_pinning else ""
    lines = [
        f"{step}. Central package management is already on{pinning} "
        f"({len(central.pinned)} versions pinned), so the fix is narrow: "
        f"**{len(missing)} of the {len(conflicts)} conflicting packages are missing "
        f"from `{PROPS_FILE}`.** Add them and the conflict resolves at the next restore.",
        "",
    ]
    lines += _truncated(missing, MAX_LISTED_UNPINNED,
                        lambda n: f"   - `{n}` - {', '.join(conflicts[n])}")
    return lines + [""]


def build_report(inventory, root, vulns=None, central=None):
    shipped = inventory.shipped()
    conflicts = inventory.conflicts()
    lines = _numbers_section(inventory, root)
    lines += _conflicts_section(conflicts)
    lines += _prerelease_section(shipped)
    lines += _advisories_section(inventory, vulns)
    lines += _dates_section(len(shipped))
    lines += _next_steps_section(conflicts, central)
    return "\n".join(lines) + "\n"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="CRA readiness for a .NET solution.")
    parser.add_argument("root", help="solution root to scan")
    parser.add_argument("--out", default=".", help="output directory")
    parser.add_argument(
        "--check-vulns",
        action="store_true",
        help="query OSV.dev; sends package names and versions to a third party",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    print(f"Scanning {args.root} ...")
    inventory = scan(args.root)
    if not inventory.graph_count:
        print(f"No {ASSETS_FILE} found. Run 'dotnet restore' first.", file=sys.stderr)
        return 1

    vulns = None
    if args.check_vulns:
        print("Querying OSV.dev ...")
        try:
            vulns = query_osv(inventory.shipped())
        except RuntimeError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2

    sbom = to_cyclonedx(inventory, args.root)
    report = build_report(inventory, args.root, vulns, read_central_packages(args.root))

    os.makedirs(args.out, exist_ok=True)
    sbom_path = os.path.join(args.out, "sbom.cdx.json")
    report_path = os.path.join(args.out, "cra-readiness.md")
    with open(sbom_path, "w", encoding="utf-8") as handle:
        json.dump(sbom, handle, indent=2)
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(report)

    shipped = len(inventory.shipped())
    print(f"  {inventory.graph_count} restore graphs, "
          f"{len(inventory.components)} components ({shipped} shipped)")
    print(f"  -> {sbom_path}")
    print(f"  -> {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
