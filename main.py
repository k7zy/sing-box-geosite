"""Build sing-box and Surge rule sets from the sources in url.yaml."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import subprocess
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from urllib.parse import urlsplit

import requests
import yaml


SOURCE_FILE = Path(__file__).with_name("url.yaml")
OUTPUT_DIR = Path(__file__).with_name("rule-set")
REQUEST_TIMEOUT = 30
MAX_WORKERS = 8

# Source formats use different names for the same match condition.
ALIASES = {
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "HOST-WILDCARD": "DOMAIN-WILDCARD",
    "IP6-CIDR": "IP-CIDR6",
    "SRC-IP-CIDR": "SRC-IP",
    "DST-PORT": "DEST-PORT",
}

SURGE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN", "USER-AGENT",
    "URL-REGEX", "PROCESS-NAME", "DEST-PORT", "SRC-PORT",
    "IN-PORT", "SRC-IP", "DEVICE-NAME", "MAC-ADDRESS",
    "PROTOCOL", "HOSTNAME-TYPE", "SUBNET", "CELLULAR-RADIO",
    "CELLULAR-CARRIER", "AND", "OR", "NOT",
}

# Fields supported by the existing sing-box source format output.
SING_BOX_FIELDS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "SRC-IP": "source_ip_cidr",
    "GEOIP": "geoip",
    "DEST-PORT": "port",
    "SRC-PORT": "source_port",
    "DOMAIN-REGEX": "domain_regex",
}

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}
OPTION_TYPES = {
    "no-resolve": IP_TYPES,
    "extended-matching": DOMAIN_TYPES | {"URL-REGEX"},
}


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str = ""
    options: tuple[str, ...] = ()
    children: tuple[Rule, ...] = ()


@dataclass(frozen=True)
class SourceResult:
    rules: tuple[Rule, ...]
    skipped: int


def _csv_fields(line: str) -> list[str]:
    return [field.strip() for field in next(csv.reader([line], skipinitialspace=True, strict=True))]


def _options(kind: str, fields: list[str]) -> tuple[str, ...]:
    # Unknown fields are source policy names, not part of a Surge rule set.
    return tuple(sorted({field.lower() for field in fields
                         if field.lower() in OPTION_TYPES
                         and kind in OPTION_TYPES[field.lower()]}))


def _bracketed_prefix(text: str) -> tuple[str, str] | None:
    """Return the first balanced parenthesized expression and its remainder."""
    if not text.startswith("("):
        return None
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[:index + 1], text[index + 1:]
    return None


def _logical_children(expression: str) -> list[str] | None:
    inner = expression[1:-1].strip()
    children = []
    while inner:
        result = _bracketed_prefix(inner)
        if result is None:
            return None
        child, inner = result
        children.append(child[1:-1].strip())
        inner = inner.strip()
        if inner:
            if not inner.startswith(","):
                return None
            inner = inner[1:].strip()
            if not inner:
                return None
    return children


def parse_rule(line: str, *, allow_bare: bool = True) -> Rule | None:
    line = line.lstrip("\ufeff").strip()
    if not line or line.startswith(("#", "//", ";")):
        return None

    if "," not in line:
        if not allow_bare or any(char.isspace() for char in line):
            return None
        if line.startswith("+.") or line.startswith("."):
            kind, value = "DOMAIN-SUFFIX", line.removeprefix("+").lstrip(".")
        else:
            try:
                version = ipaddress.ip_network(line, strict=False).version
            except ValueError:
                kind, value = "DOMAIN", line
            else:
                kind, value = ("IP-CIDR" if version == 4 else "IP-CIDR6"), line
        if not value or (kind in DOMAIN_TYPES and any(char in value for char in ":/;#")):
            return None
        return Rule(kind, value.lower() if kind in DOMAIN_TYPES else value)

    raw_kind, rest = line.split(",", 1)
    kind = ALIASES.get(raw_kind.strip().upper(), raw_kind.strip().upper())
    if kind in {"AND", "OR", "NOT"}:
        result = _bracketed_prefix(rest.strip())
        if result is None:
            return None
        expression, tail = result
        parts = _logical_children(expression)
        if parts is None or len(parts) < (1 if kind == "NOT" else 2):
            return None
        if kind == "NOT" and len(parts) != 1:
            return None
        children = tuple(parse_rule(part, allow_bare=False) for part in parts)
        if any(child is None or child.kind not in SURGE_TYPES for child in children):
            return None
        if tail and not tail.startswith(","):
            return None
        return Rule(kind, children=children)

    if kind not in SURGE_TYPES and kind not in SING_BOX_FIELDS:
        return None
    try:
        fields = _csv_fields(rest)
    except csv.Error:
        return None
    value = fields[0].strip("'\"") if fields else ""
    if not value:
        return None
    if kind == "DOMAIN-SUFFIX":
        value = value.removeprefix("+").lstrip(".")
    if kind in DOMAIN_TYPES:
        value = value.lower()
    if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP"}:
        try:
            version = ipaddress.ip_network(value, strict=False).version
        except ValueError:
            return None
        if (kind == "IP-CIDR" and version != 4) or (kind == "IP-CIDR6" and version != 6):
            return None
    if not value or "\n" in value or "\r" in value:
        return None
    return Rule(kind, value, _options(kind, fields[1:]))


def parse_source(url: str, content: str) -> SourceResult:
    suffix = Path(urlsplit(url).path).suffix.lower()
    if suffix in {".yaml", ".yml"} or content.lstrip().startswith("payload:"):
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            items = data.get("payload")
            if not isinstance(items, list):
                raise ValueError("YAML payload must be a list")
        elif isinstance(data, list):
            items = data
        elif isinstance(data, str):
            items = data.splitlines()
        else:
            raise ValueError("Unsupported YAML source")
    else:
        items = content.splitlines()

    rules = []
    skipped = 0
    for item in items:
        if not isinstance(item, str):
            skipped += 1
            continue
        stripped = item.strip()
        if not stripped or stripped.startswith(("#", "//", ";")):
            continue
        rule = parse_rule(stripped)
        if rule is None:
            skipped += 1
        else:
            rules.append(rule)
    return SourceResult(tuple(rules), skipped)


def fetch_source(url: str) -> SourceResult:
    response = requests.get(url, headers={"User-Agent": "sing-box-geosite/1.0"}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return parse_source(url, response.text)


def surge_line(rule: Rule) -> str:
    if rule.children:
        children = ",".join(f"({surge_line(child)})" for child in rule.children)
        return f"{rule.kind},({children})"
    buffer = StringIO()
    csv.writer(buffer, lineterminator="\n").writerow([rule.kind, rule.value, *rule.options])
    return buffer.getvalue().rstrip("\n")


def sing_box_rule(rule: Rule) -> dict | None:
    if rule.children:
        children = [sing_box_rule(child) for child in rule.children]
        if any(child is None for child in children):
            return None
        if rule.kind == "NOT":
            return {**children[0], "invert": not children[0].get("invert", False)}
        return {"type": "logical", "mode": rule.kind.lower(), "rules": children}
    field = SING_BOX_FIELDS.get(rule.kind)
    return {field: rule.value} if field else None


def build_outputs(rules: list[Rule]) -> tuple[str, str]:
    unique = list(dict.fromkeys(rules))
    surge = sorted((rule for rule in unique if rule.kind in SURGE_TYPES),
                   key=lambda rule: (rule.kind in IP_TYPES, surge_line(rule)))
    list_text = "\n".join(surge_line(rule) for rule in surge) + "\n"

    fields: dict[str, set[str]] = defaultdict(set)
    logical: dict[str, dict] = {}
    for rule in unique:
        converted = sing_box_rule(rule)
        if converted is None:
            continue
        if rule.children:
            logical[json.dumps(converted, sort_keys=True)] = converted
        else:
            field, value = next(iter(converted.items()))
            fields[field].add(value)
    entries = [{field: sorted(fields[field])} for field in sorted(fields)]
    entries.extend(logical[key] for key in sorted(logical))
    json_text = json.dumps({"version": 2, "rules": entries}, ensure_ascii=False, indent=2) + "\n"
    return list_text, json_text


def write_group(name: str, rules: list[Rule], output_dir: Path = OUTPUT_DIR) -> None:
    list_text, json_text = build_outputs(rules)
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=output_dir) as temp_dir:
        stage = Path(temp_dir)
        json_path = stage / f"{name}.json"
        list_path = stage / f"{name}.list"
        srs_path = stage / f"{name}.srs"
        json_path.write_text(json_text, encoding="utf-8")
        list_path.write_text(list_text, encoding="utf-8")
        subprocess.run(["sing-box", "rule-set", "compile", "--output", str(srs_path), str(json_path)], check=True)
        for path in (json_path, list_path, srs_path):
            os.replace(path, output_dir / path.name)


def main() -> int:
    with SOURCE_FILE.open(encoding="utf-8") as file:
        groups = yaml.safe_load(file)
    if not isinstance(groups, dict):
        raise ValueError("url.yaml must map group names to URL lists")
    if any(not isinstance(urls, list) or not all(isinstance(url, str) for url in urls)
           for urls in groups.values()):
        raise ValueError("Each url.yaml group must contain a list of URLs")

    urls = dict.fromkeys(url for group in groups.values() for url in group)
    failed_groups = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {url: executor.submit(fetch_source, url) for url in urls}
        for name, sources in groups.items():
            rules = []
            successes = 0
            for url in sources:
                try:
                    result = futures[url].result()
                except (requests.RequestException, ValueError, yaml.YAMLError) as error:
                    print(f"警告：跳过 {url}：{error}")
                    continue
                successes += 1
                rules.extend(result.rules)
                if result.skipped:
                    print(f"警告：{url} 中跳过 {result.skipped} 条无法转换的规则")
            if not successes or not any(rule.kind in SURGE_TYPES for rule in rules):
                print(f"错误：{name} 没有可用的 Surge 规则，保留已有产物")
                failed_groups.append(name)
                continue
            print(f"生成 {name}: {len(rules)} 条原始规则")
            write_group(name, rules)
    return 1 if failed_groups else 0


if __name__ == "__main__":
    raise SystemExit(main())
