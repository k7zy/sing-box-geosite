import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main


class RuleParsingTests(unittest.TestCase):
    def test_mixed_sources_make_valid_surge_rules_and_deduplicated_json(self):
        surge_source = main.parse_source(
            "https://example.test/source.list",
            "\n".join([
                "# comment",
                "HOST-SUFFIX,Example.com,Telegram",
                "HOST-WILDCARD,example.*,Telegram",
                "IP6-CIDR,2001:db8::/32,Telegram,no-resolve",
                "IP-ASN,13335,Telegram",
                "USER-AGENT,Test*,Telegram",
                "PROCESS-NAME,trustd",
                "+.example.com",
                "DOMAIN-SUFFIX,example.com",
                "UNKNOWN,ignored",
            ]),
        )
        yaml_source = main.parse_source(
            "https://example.test/source.yaml",
            "payload:\n  - +.example.com\n  - plain.example.com\n  - 192.0.2.0/24\n",
        )
        self.assertEqual(surge_source.skipped, 1)
        list_text, json_text = main.build_outputs([*surge_source.rules, *yaml_source.rules])
        lines = list_text.splitlines()
        self.assertEqual(lines.count("DOMAIN-SUFFIX,example.com"), 1)
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve", lines)
        self.assertIn("IP-ASN,13335", lines)
        self.assertIn("USER-AGENT,Test*", lines)
        self.assertIn("PROCESS-NAME,trustd", lines)
        self.assertIn("DOMAIN,plain.example.com", lines)
        self.assertIn("DOMAIN-WILDCARD,example.*", lines)
        self.assertIn("IP-CIDR,192.0.2.0/24", lines)
        self.assertTrue(all(main.parse_rule(line) for line in lines))
        self.assertFalse(any("Telegram" in line for line in lines))

        rules = json.loads(json_text)["rules"]
        self.assertIn({"domain_suffix": ["example.com"]}, rules)
        self.assertIn({"domain": ["plain.example.com"]}, rules)
        self.assertIn({"ip_cidr": ["192.0.2.0/24", "2001:db8::/32"]}, rules)
        self.assertFalse(any("IP-ASN" in str(rule) for rule in rules))

    def test_logical_rule_and_quoted_comma_round_trip(self):
        rule = main.parse_rule(
            "AND,((HOST-SUFFIX,Example.com),(IP-CIDR,192.0.2.0/24)),Proxy"
        )
        self.assertIsNotNone(rule)
        self.assertEqual(
            main.surge_line(rule),
            "AND,((DOMAIN-SUFFIX,example.com),(IP-CIDR,192.0.2.0/24))",
        )
        self.assertEqual(main.parse_rule(main.surge_line(rule)), rule)
        self.assertEqual(main.sing_box_rule(rule)["mode"], "and")

        regex = main.parse_rule('URL-REGEX,"^https://example.com/a,b",Proxy')
        self.assertEqual(main.surge_line(regex), 'URL-REGEX,"^https://example.com/a,b"')
        self.assertEqual(main.parse_rule(main.surge_line(regex)), regex)
        self.assertIsNone(main.sing_box_rule(regex))

    def test_surge_rejects_unsupported_and_malformed_lines(self):
        self.assertIsNone(main.parse_rule("FINAL,Proxy"))
        self.assertIsNone(main.parse_rule("IP-CIDR,not-an-ip"))
        self.assertIsNone(main.parse_rule("AND,((DOMAIN,one.example))"))
        self.assertEqual(main.build_outputs([main.parse_rule("DOMAIN-REGEX,^foo")])[0], "\n")


class GenerationTests(unittest.TestCase):
    def test_failed_source_is_skipped_but_empty_group_is_not_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_file = Path(temp_dir) / "url.yaml"
            source_file.write_text(
                "good:\n  - https://example.test/ok.list\n  - https://example.test/down.list\n"
                "empty:\n  - https://example.test/down.list\n",
                encoding="utf-8",
            )

            def fetch(url):
                if "down" in url:
                    raise ValueError("download failed")
                return main.SourceResult((main.Rule("DOMAIN", "example.com"),), 0)

            with mock.patch.object(main, "SOURCE_FILE", source_file), \
                 mock.patch.object(main, "fetch_source", side_effect=fetch), \
                 mock.patch.object(main, "write_group") as write:
                self.assertEqual(main.main(), 1)
            write.assert_called_once_with("good", [main.Rule("DOMAIN", "example.com")])

    def test_compile_failure_does_not_replace_existing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            for suffix in ("json", "list", "srs"):
                (output_dir / f"demo.{suffix}").write_text("old", encoding="utf-8")
            with mock.patch.object(main.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "sing-box")):
                with self.assertRaises(subprocess.CalledProcessError):
                    main.write_group("demo", [main.Rule("DOMAIN", "example.com")], output_dir)
            for suffix in ("json", "list", "srs"):
                self.assertEqual((output_dir / f"demo.{suffix}").read_text(), "old")


if __name__ == "__main__":
    unittest.main()
