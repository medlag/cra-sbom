import json
import os
import tempfile
import unittest

import cra_sbom


def write_graph(root, project, *, targets, declared, libraries=None):
    obj_dir = os.path.join(root, project, "obj")
    os.makedirs(obj_dir, exist_ok=True)
    libs = libraries if libraries is not None else {
        key: {"type": "package", "sha512": f"sha-{key}"}
        for target in targets.values() for key in target
    }
    for target in targets.values():
        for entry in target.values():
            entry.setdefault("type", "package")
    doc = {
        "targets": targets,
        "libraries": libs,
        "projectFileDependencyGroups": {"net9.0": declared},
        "project": {"restore": {"projectName": project}},
    }
    with open(os.path.join(obj_dir, "project.assets.json"), "w", encoding="utf-8") as handle:
        json.dump(doc, handle)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_parents_are_attributed_only_to_the_resolved_version(self):
        write_graph(self.root, "Api", targets={"net9.0": {
            "Azure.Identity/1.16.0": {"dependencies": {"Microsoft.Identity.Client": "4.77.1"}},
            "Microsoft.Identity.Client/4.77.1": {},
        }}, declared=["Azure.Identity >= 1.16.0"])
        write_graph(self.root, "Tools", targets={"net9.0": {
            "Microsoft.Data.SqlClient/5.0.0": {"dependencies": {"Microsoft.Identity.Client": "4.61.3"}},
            "Microsoft.Identity.Client/4.61.3": {},
        }}, declared=["Microsoft.Data.SqlClient >= 5.0.0"])

        inventory = cra_sbom.scan(self.root)

        self.assertEqual(
            {"Azure.Identity"},
            inventory.components[("Microsoft.Identity.Client", "4.77.1")].parents,
        )
        self.assertEqual(
            {"Microsoft.Data.SqlClient"},
            inventory.components[("Microsoft.Identity.Client", "4.61.3")].parents,
        )

    def test_a_project_reference_is_not_reported_as_a_parent_package(self):
        write_graph(self.root, "Api", targets={"net9.0": {
            "Shared/1.0.0": {"type": "project", "dependencies": {"Serilog": "3.0.0"}},
            "Serilog/3.0.0": {"type": "package"},
        }}, declared=["Serilog >= 3.0.0"],
            libraries={"Serilog/3.0.0": {"type": "package", "sha512": "x"},
                       "Shared/1.0.0": {"type": "project"}})

        inventory = cra_sbom.scan(self.root)

        self.assertEqual(set(), inventory.components[("Serilog", "3.0.0")].parents)

    def test_dependency_on_an_unresolved_version_is_not_attributed(self):
        write_graph(self.root, "Api", targets={"net9.0": {
            "Parent/1.0.0": {"dependencies": {"Ghost": "9.9.9"}},
        }}, declared=["Parent >= 1.0.0"])

        inventory = cra_sbom.scan(self.root)

        self.assertNotIn(("Ghost", "9.9.9"), inventory.components)

    def test_transitively_pinned_packages_are_not_counted_as_direct(self):
        obj_dir = os.path.join(self.root, "Api", "obj")
        os.makedirs(obj_dir)
        doc = {
            "targets": {"net9.0": {"Serilog/3.0.0": {}}},
            "libraries": {"Serilog/3.0.0": {"type": "package", "sha512": "x"}},
            "projectFileDependencyGroups": {"net9.0": []},
            "centralTransitiveDependencyGroups": {"net9.0": {"Serilog": "3.0.0"}},
            "project": {"restore": {"projectName": "Api"}},
        }
        with open(os.path.join(obj_dir, "project.assets.json"), "w", encoding="utf-8") as handle:
            json.dump(doc, handle)

        inventory = cra_sbom.scan(self.root)

        self.assertFalse(inventory.components[("Serilog", "3.0.0")].is_direct)

    def test_test_projects_are_excluded_from_shipped_components(self):
        write_graph(self.root, "Api", targets={"net9.0": {"Serilog/3.0.0": {}}},
                    declared=["Serilog >= 3.0.0"])
        write_graph(self.root, "Api.UnitTests", targets={"net9.0": {"Moq/4.20.0": {}}},
                    declared=["Microsoft.NET.Test.Sdk >= 17.0.0", "Moq >= 4.20.0"])

        inventory = cra_sbom.scan(self.root)

        self.assertTrue(inventory.components[("Serilog", "3.0.0")].shipped)
        self.assertFalse(inventory.components[("Moq", "4.20.0")].shipped)
        self.assertEqual({"Api.UnitTests"}, inventory.test_projects)

    def test_a_shipping_project_using_an_assertion_library_is_not_treated_as_a_test(self):
        write_graph(self.root, "Api", targets={"net9.0": {"FluentAssertions/6.0.0": {}}},
                    declared=["FluentAssertions >= 6.0.0"])

        inventory = cra_sbom.scan(self.root)

        self.assertEqual(set(), inventory.test_projects)
        self.assertTrue(inventory.components[("FluentAssertions", "6.0.0")].shipped)

    def test_project_type_libraries_are_not_components(self):
        write_graph(self.root, "Api", targets={"net9.0": {"Shared/1.0.0": {}}},
                    declared=["Shared >= 1.0.0"],
                    libraries={"Shared/1.0.0": {"type": "project"}})

        inventory = cra_sbom.scan(self.root)

        self.assertEqual({}, inventory.components)

    def test_conflicts_report_every_shipped_version(self):
        write_graph(self.root, "A", targets={"net9.0": {"Serilog/3.0.0": {}}},
                    declared=["Serilog >= 3.0.0"])
        write_graph(self.root, "B", targets={"net9.0": {"Serilog/4.0.0": {}}},
                    declared=["Serilog >= 4.0.0"])

        self.assertEqual({"Serilog": ["3.0.0", "4.0.0"]}, cra_sbom.scan(self.root).conflicts())

    def test_a_malformed_graph_is_skipped_not_fatal(self):
        write_graph(self.root, "Good", targets={"net9.0": {"Serilog/3.0.0": {}}},
                    declared=["Serilog >= 3.0.0"])
        broken = os.path.join(self.root, "Bad", "obj")
        os.makedirs(broken)
        with open(os.path.join(broken, "project.assets.json"), "w", encoding="utf-8") as handle:
            handle.write("{not json")

        inventory = cra_sbom.scan(self.root)

        self.assertEqual(1, inventory.graph_count)


class CycloneDxTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_bom_carries_purl_scope_and_hash(self):
        write_graph(self.root, "Api", targets={"net9.0": {"Serilog/3.0.0": {}}},
                    declared=["Serilog >= 3.0.0"])

        bom = cra_sbom.to_cyclonedx(cra_sbom.scan(self.root), self.root)

        self.assertEqual("CycloneDX", bom["bomFormat"])
        self.assertEqual("1.6", bom["specVersion"])
        component = bom["components"][0]
        self.assertEqual("pkg:nuget/Serilog@3.0.0", component["purl"])
        self.assertEqual("required", component["scope"])
        self.assertEqual("SHA-512", component["hashes"][0]["alg"])

    def test_test_only_components_are_scoped_optional(self):
        write_graph(self.root, "Api.Tests", targets={"net9.0": {"Moq/4.20.0": {}}},
                    declared=["Microsoft.NET.Test.Sdk >= 17.0.0"])

        bom = cra_sbom.to_cyclonedx(cra_sbom.scan(self.root), self.root)

        self.assertEqual("optional", bom["components"][0]["scope"])


class CentralPackagesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_reads_flags_and_pinned_versions(self):
        with open(os.path.join(self.root, "Directory.Packages.props"), "w", encoding="utf-8") as h:
            h.write("""<Project><PropertyGroup>
                <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
                <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>
                </PropertyGroup><ItemGroup>
                <PackageVersion Include="Serilog" Version="3.0.0" />
                </ItemGroup></Project>""")

        central = cra_sbom.read_central_packages(self.root)

        self.assertTrue(central.enabled)
        self.assertTrue(central.transitive_pinning)
        self.assertEqual({"Serilog"}, central.pinned)

    def test_absent_file_reports_none(self):
        self.assertIsNone(cra_sbom.read_central_packages(self.root))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_remedy_names_only_the_conflicts_missing_from_central_pins(self):
        write_graph(self.root, "A", targets={"net9.0": {"Serilog/3.0.0": {}}},
                    declared=["Serilog >= 3.0.0"])
        write_graph(self.root, "B", targets={"net9.0": {"Serilog/4.0.0": {}}},
                    declared=["Serilog >= 4.0.0"])
        central = cra_sbom.CentralPackages("props", True, True, {"Newtonsoft.Json"})

        report = cra_sbom.build_report(cra_sbom.scan(self.root), self.root, None, central)

        self.assertIn("already on with transitive pinning", report)
        self.assertIn("**1 of the 1 conflicting packages", report)

    def test_advisory_section_states_provenance(self):
        write_graph(self.root, "Api", targets={"net9.0": {
            "Azure.Identity/1.16.0": {"dependencies": {"Microsoft.Identity.Client": "4.77.1"}},
            "Microsoft.Identity.Client/4.77.1": {},
        }}, declared=["Azure.Identity >= 1.16.0"])
        vulns = {("Microsoft.Identity.Client", "4.77.1"): ["GHSA-x"]}

        report = cra_sbom.build_report(cra_sbom.scan(self.root), self.root, vulns)

        self.assertIn("1 advisory: GHSA-x", report)
        self.assertIn("Pulled in by `Azure.Identity`", report)
        self.assertIn("bump the parent", report)

    def test_clean_scan_says_so_explicitly(self):
        write_graph(self.root, "Api", targets={"net9.0": {"Serilog/3.0.0": {}}},
                    declared=["Serilog >= 3.0.0"])

        report = cra_sbom.build_report(cra_sbom.scan(self.root), self.root, {})

        self.assertIn("No known advisories", report)


class MainTests(unittest.TestCase):
    def test_missing_graphs_exit_with_one(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(1, cra_sbom.main([empty, "--out", empty]))

    def test_successful_run_writes_both_artefacts(self):
        with tempfile.TemporaryDirectory() as root:
            write_graph(root, "Api", targets={"net9.0": {"Serilog/3.0.0": {}}},
                        declared=["Serilog >= 3.0.0"])
            out = os.path.join(root, "out")

            self.assertEqual(0, cra_sbom.main([root, "--out", out]))
            self.assertTrue(os.path.exists(os.path.join(out, "sbom.cdx.json")))
            self.assertTrue(os.path.exists(os.path.join(out, "cra-readiness.md")))


if __name__ == "__main__":
    unittest.main()
