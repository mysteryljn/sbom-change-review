"""Release-oriented comparison of CycloneDX and SPDX component inventories."""
from collections import Counter, defaultdict
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote


class InputError(ValueError):
    """The document is not within the supported input contract."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON object member: " + key)
        result[key] = value
    return result


def load(path):
    with Path(path).open(encoding="utf-8-sig") as stream:
        value = json.load(stream, object_pairs_hook=_object)
    return normalize(value)


def _text(value, field, required=False):
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise InputError(field + " must be a non-empty string" if required else field + " must be a string")
    return value.strip()


def package_identity(purl):
    """Remove only purl version; preserve namespace, qualifiers and subpath."""
    purl = _text(purl, "purl", True)
    if not purl.startswith("pkg:"):
        raise InputError("purl must begin with pkg:")
    body, _, subpath = purl[4:].partition("#")
    body, _, query = body.partition("?")
    package, at, version = body.rpartition("@")
    if not at:
        package, version = body, ""
    kind, slash, name = package.partition("/")
    if not slash or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9.+-]*", kind) or not name:
        raise InputError("purl requires a package type and name")
    if at and not version:
        raise InputError("purl version must not be empty after @")
    qualifiers = parse_qsl(query, keep_blank_values=True)
    if any(not k or not v for k, v in qualifiers) or len({k.lower() for k, _ in qualifiers}) != len(qualifiers):
        raise InputError("purl qualifiers must have distinct keys and non-empty values")
    # Re-encode components so equivalent escaped spellings match, while an
    # encoded slash in a package segment does not become a namespace boundary.
    name = "/".join(quote(unquote(part), safe="-._~") for part in name.split("/"))
    normalized = "pkg:" + kind.lower() + "/" + name
    if qualifiers:
        normalized += "?" + "&".join(quote(k.lower(), safe="-._~") + "=" + quote(v, safe="-._~") for k, v in sorted(qualifiers, key=lambda pair: pair[0].lower()))
    if subpath:
        normalized += "#" + "/".join(quote(unquote(part), safe="-._~") for part in subpath.split("/"))
    return normalized, unquote(version)


def _licenses_cdx(component):
    choices = component.get("licenses", [])
    if not isinstance(choices, list):
        raise InputError("component licenses must be an array")
    values = []
    for choice in choices:
        if not isinstance(choice, dict):
            raise InputError("license choice must be an object")
        if "expression" in choice:
            values.append(_text(choice["expression"], "license expression", True))
        elif isinstance(choice.get("license"), dict):
            license_data = choice["license"]
            values.append(_text(license_data.get("id") or license_data.get("name"), "license id or name", True))
        else:
            raise InputError("license choice needs expression or license")
    return sorted(set(values))


def _record(component, fmt):
    if not isinstance(component, dict):
        raise InputError("every component/package must be an object")
    name = _text(component.get("name"), "component name", True)
    group = _text(component.get("group"), "component group") if fmt == "CycloneDX" else ""
    version = _text(component.get("version" if fmt == "CycloneDX" else "versionInfo"), "component version")
    source_ref = _text(component.get("bom-ref" if fmt == "CycloneDX" else "SPDXID"), "component reference")
    purl = component.get("purl") if fmt == "CycloneDX" else None
    if fmt == "SPDX":
        refs = component.get("externalRefs", [])
        if not isinstance(refs, list) or any(not isinstance(ref, dict) for ref in refs):
            raise InputError("SPDX externalRefs must be an array of objects")
        purls = {ref.get("referenceLocator") for ref in refs if ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str)}
        if len(purls) > 1:
            raise InputError("SPDX package has multiple different purl references")
        purl = next(iter(purls), None)
        declared = _text(component.get("licenseDeclared"), "licenseDeclared")
        concluded = _text(component.get("licenseConcluded"), "licenseConcluded")
        # Prefer the analyst's conclusion; NOASSERTION means no conclusion.
        license_value = concluded if concluded and concluded != "NOASSERTION" else declared
        licenses = [license_value] if license_value else []
    else:
        licenses = _licenses_cdx(component)
    if purl is not None:
        identity, purl_version = package_identity(purl)
        if version and purl_version and version != purl_version:
            raise InputError("component version disagrees with purl version: " + name)
        version = version or purl_version
        identity_method = "purl"
    else:
        # Tuple-as-JSON avoids collisions between a slash in name and group.
        identity = "name:" + json.dumps([group, name], ensure_ascii=True, separators=(",", ":"))
        identity_method = "group/name"
    return {"identity": identity, "identity_method": identity_method,
            "name": name, "group": group, "version": version or None,
            "licenses": licenses, "source_ref": source_ref or None}


def normalize(document):
    if not isinstance(document, dict):
        raise InputError("SBOM must be a JSON object")
    if document.get("bomFormat") == "CycloneDX":
        if document.get("specVersion") not in ("1.5", "1.6"):
            raise InputError("supported CycloneDX versions are 1.5 and 1.6")
        fmt, version = "CycloneDX", document["specVersion"]
        records = document.get("components", [])
        if not isinstance(records, list):
            raise InputError("CycloneDX components must be an array")
        pending = list(reversed(records))
        records = []
        while pending:
            component = pending.pop()
            records.append(component)
            if isinstance(component, dict):
                children = component.get("components", [])
                if not isinstance(children, list):
                    raise InputError("nested components must be an array")
                pending.extend(reversed(children))
    elif document.get("spdxVersion") == "SPDX-2.3":
        fmt, version = "SPDX", "2.3"
        records = document.get("packages", [])
        if not isinstance(records, list):
            raise InputError("SPDX packages must be an array")
    else:
        raise InputError("expected CycloneDX JSON 1.5/1.6 or SPDX JSON 2.3")
    components = [_record(record, fmt) for record in records]
    components.sort(key=lambda item: (item["identity"], item["version"] or "", tuple(item["licenses"]), item["source_ref"] or ""))
    return {"format": fmt, "spec_version": version, "components": components}


def _signature(component):
    return component["version"], tuple(component["licenses"])


def _unknown_licenses(licenses):
    return not licenses or any(value.upper() in {"NOASSERTION", "NONE", "UNKNOWN"} for value in licenses)


def compare(before, after, deny_licenses=(), deny_new=False, deny_unknown=False, deny_ambiguous=False):
    groups = []
    for inventory in (before, after):
        grouped = defaultdict(list)
        for component in inventory["components"]:
            grouped[component["identity"]].append(component)
        groups.append(grouped)
    changes = []
    for identity in sorted(set(groups[0]) | set(groups[1])):
        left, right = groups[0].get(identity, []), groups[1].get(identity, [])
        if Counter(map(_signature, left)) == Counter(map(_signature, right)):
            continue
        if not left:
            kind, fields = "added", ["component"]
        elif not right:
            kind, fields = "removed", ["component"]
        elif len(left) != 1 or len(right) != 1:
            kind, fields = "ambiguous", ["inventory"]
        else:
            kind = "changed"
            fields = [field for field in ("version", "licenses") if left[0][field] != right[0][field]]
        changes.append({"kind": kind, "identity": identity, "fields": fields, "before": left, "after": right})
    denied = sorted(set(deny_licenses))
    violations = []
    for change in changes:
        if deny_new and change["kind"] == "added":
            violations.append({"rule": "new-component", "identity": change["identity"], "detail": "identity was not in the baseline"})
        if deny_ambiguous and change["kind"] == "ambiguous":
            violations.append({"rule": "ambiguous-change", "identity": change["identity"], "detail": "multiple records prevent one-to-one change attribution"})
    for component in after["components"]:
        for license_value in component["licenses"]:
            tokens = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", license_value))
            for forbidden in denied:
                if forbidden == license_value or forbidden in tokens:
                    violations.append({"rule": "denied-license", "identity": component["identity"], "detail": forbidden + " occurs in " + license_value})
        if deny_unknown and _unknown_licenses(component["licenses"]):
            violations.append({"rule": "unknown-license", "identity": component["identity"], "detail": "license is missing or unresolved"})
    counts = Counter(change["kind"] for change in changes)
    return {"schema_version": 1, "tool": "sbom-change-review", "before": before, "after": after,
            "summary": {"before_components": len(before["components"]), "after_components": len(after["components"]),
                        **{kind: counts[kind] for kind in ("added", "removed", "changed", "ambiguous")}},
            "changes": changes, "policy": {"deny_licenses": denied, "deny_new": deny_new, "deny_unknown_license": deny_unknown, "deny_ambiguous": deny_ambiguous},
            "violations": violations, "passed": not violations}
