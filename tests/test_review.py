import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from sbom_change_review.cli import main
from sbom_change_review.core import InputError, compare, load, normalize, package_identity
from sbom_change_review.report import render


FIXTURES = Path(__file__).parents[1] / "sbom_change_review" / "fixtures"


def component(name="motor", version="1", license_id="MIT", **extra):
    value = {"name": name, "version": version, "type": "library", "licenses": [{"license": {"id": license_id}}]}
    value.update(extra)
    return value


def cdx(*components):
    return normalize({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)})


class ReviewTests(unittest.TestCase):
    def test_fixture_has_four_distinct_change_kinds(self):
        report = compare(load(FIXTURES / "before.cdx.json"), load(FIXTURES / "after.cdx.json"))
        self.assertEqual({item["kind"] for item in report["changes"]}, {"added", "removed", "changed", "ambiguous"})
        self.assertTrue(report["passed"])

    def test_document_local_bom_refs_are_not_identity(self):
        a = cdx(component(**{"bom-ref": "a"}))
        b = cdx(component(**{"bom-ref": "different"}))
        self.assertEqual(compare(a, b)["changes"], [])
        renamed = cdx(component(name="other", **{"bom-ref": "a"}))
        self.assertEqual({c["kind"] for c in compare(a, renamed)["changes"]}, {"added", "removed"})

    def test_cdx_spdx_purl_identity_matches_across_documents(self):
        a = cdx(component(name="gateway-core", version="1.2.0", purl="pkg:pypi/gateway-core@1.2.0"))
        changes = compare(a, load(FIXTURES / "current.spdx.json"))["changes"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["fields"], ["version", "licenses"])

    def test_qualifier_order_normalized_and_version_removed(self):
        a, v = package_identity("pkg:npm/%40scope/a@2?os=linux&arch=arm")
        b, _ = package_identity("pkg:npm/%40scope/a@1?arch=arm&os=linux")
        self.assertEqual(a, b)
        self.assertEqual(v, "2")
        self.assertNotEqual(a, package_identity("pkg:npm/%40scope/a@2?os=linux&arch=x86")[0])

    def test_purl_version_conflict_rejected(self):
        with self.assertRaises(InputError):
            cdx(component(version="1", purl="pkg:generic/motor@2"))

    def test_missing_version_can_come_from_purl(self):
        record = component(purl="pkg:generic/motor@2")
        record.pop("version")
        self.assertEqual(cdx(record)["components"][0]["version"], "2")

    def test_duplicate_qualifiers_rejected(self):
        with self.assertRaises(InputError):
            package_identity("pkg:generic/motor@1?arch=a&ARCH=b")

    def test_order_and_license_order_do_not_create_changes(self):
        a = component(); a["licenses"].append({"license": {"id": "BSD-3-Clause"}})
        b = copy.deepcopy(a); b["licenses"].reverse()
        self.assertEqual(compare(cdx(a, component("x")), cdx(component("x"), b))["changes"], [])

    def test_multiversion_change_is_ambiguous_not_false_upgrade(self):
        a = cdx(component(version="1"), component(version="2"))
        b = cdx(component(version="1"), component(version="3"))
        report = compare(a, b, deny_ambiguous=True)
        self.assertEqual(report["changes"][0]["kind"], "ambiguous")
        self.assertEqual(len(report["changes"][0]["before"]), 2)
        self.assertFalse(report["passed"])

    def test_duplicate_occurrences_are_not_discarded(self):
        report = compare(cdx(component(), component()), cdx(component()))
        self.assertEqual(report["summary"]["before_components"], 2)
        self.assertEqual(report["changes"][0]["kind"], "ambiguous")
        self.assertEqual(compare(cdx(component(), component()), cdx(component(), component()))["changes"], [])

    def test_missing_licenses_policy_checks_unchanged_inventory(self):
        item = component(); item.pop("licenses")
        report = compare(cdx(item), cdx(item), deny_unknown=True)
        self.assertFalse(report["passed"])
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["violations"][0]["rule"], "unknown-license")

    def test_license_expression_denied_identifier_is_conservative(self):
        item = component(); item["licenses"] = [{"expression": "MIT OR GPL-3.0-only"}]
        report = compare(cdx(), cdx(item), deny_licenses=["GPL-3.0-only"])
        self.assertFalse(report["passed"])
        self.assertTrue(compare(cdx(), cdx(item), deny_licenses=["GPL-3.0"])["passed"])

    def test_new_policy_does_not_block_version_change(self):
        self.assertTrue(compare(cdx(component()), cdx(component(version="2")), deny_new=True)["passed"])
        self.assertFalse(compare(cdx(), cdx(component()), deny_new=True)["passed"])

    def test_nested_components_included(self):
        a = component(); a["components"] = [component("nested")]
        self.assertEqual(len(cdx(a)["components"]), 2)

    def test_group_and_slash_names_do_not_collide(self):
        a = cdx(component(name="b", group="a"), component(name="a/b"))
        self.assertEqual(len({c["identity"] for c in a["components"]}), 2)

    def test_empty_sbom_is_allowed_and_removals_visible(self):
        report = compare(cdx(component()), cdx())
        self.assertEqual(report["summary"]["removed"], 1)

    def test_unsupported_version_and_bad_shapes_rejected(self):
        for data in ([], {"bomFormat": "CycloneDX", "specVersion": "1.4"}, {"spdxVersion": "SPDX-2.2"}, {"spdxVersion": "SPDX-2.3", "packages": {}}, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [None]}):
            with self.subTest(data=data), self.assertRaises(InputError):
                normalize(data)

    def test_unknown_version_is_visible_not_zero(self):
        item = component(); item.pop("version")
        report = compare(cdx(), cdx(item))
        self.assertIsNone(report["after"]["components"][0]["version"])
        self.assertIn("unknown version", render(report, "html"))

    def test_html_and_markdown_escape_untrusted_fields(self):
        report = compare(cdx(), cdx(component(name="<img src=x onerror=alert(1)>|`")))
        self.assertNotIn("<img", render(report, "html"))
        markdown = render(report, "markdown")
        self.assertIn("&lt;img", markdown)
        self.assertIn("&#124;", markdown)

    def test_cli_demo_all_formats_without_cwd_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extension in ("html", "json", "md"):
                output = Path(tmp) / ("demo." + extension)
                self.assertEqual(main(["demo", "--output", str(output)]), 0)
                self.assertGreater(output.stat().st_size, 100)

    def test_cli_policy_exit_one_report_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "review.json"
            self.assertEqual(main(["demo", "--deny-new", "--output", str(output)]), 1)
            self.assertFalse(json.loads(output.read_text())["passed"])

    def test_cli_bad_json_exit_two_keeps_previous_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            invalid = Path(tmp) / "bad.json"; invalid.write_text("{", encoding="utf8")
            output = Path(tmp) / "report.html"; output.write_text("previous", encoding="utf8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["compare", str(invalid), str(invalid), "--output", str(output)]), 2)
            self.assertEqual(output.read_text(), "previous")

    def test_duplicate_json_members_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            invalid = Path(tmp) / "bad.json"; invalid.write_text('{"spdxVersion":"SPDX-2.3","packages":[],"packages":[]}')
            with self.assertRaises(InputError):
                load(invalid)

    def test_output_cannot_overwrite_source(self):
        with contextlib.redirect_stderr(io.StringIO()):
            path = str(FIXTURES / "before.cdx.json")
            self.assertEqual(main(["compare", path, path, "--output", path]), 2)


if __name__ == "__main__":
    unittest.main()
