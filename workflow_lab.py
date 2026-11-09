"""Offline regression tools for the Workflows AD offboarding preview."""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_INPUT_BYTES = 1024 * 1024
EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
SID = re.compile(r"S-1-5-21(?:-(?:0|[1-9][0-9]{0,9})){4}")
EVENT_ID = re.compile(r"[1-9][0-9]{0,4}")
RECORD_ID = re.compile(r"[1-9][0-9]{0,19}")
OKTA_ID = re.compile(r"00u[A-Za-z0-9]{17}")
CASE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
EVENT_FIELDS = {"event_id", "source_host", "target_sid", "record_id"}


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def read_text(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("Input exceeds 1 MiB")
    return data.decode("utf-8-sig")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains a duplicate key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("JSON contains a non-standard numeric value")


def read_json(path):
    return json.loads(
        read_text(path), object_pairs_hook=unique_object, parse_constant=reject_constant
    )


def valid_event(event):
    return (
        isinstance(event, dict)
        and event.keys() == EVENT_FIELDS
        and matches(EVENT_ID, event["event_id"])
        and matches(HOST, event["source_host"])
        and matches(SID, event["target_sid"])
        and matches(RECORD_ID, event["record_id"])
    )


def normalize_event(xml):
    """Convert a single Windows Security 4725 XML record into the flow input."""
    if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", xml, re.IGNORECASE) or "\x00" in xml:
        raise ValueError("XML must be UTF-8 without a DTD or entity declaration")
    root = ET.fromstring(xml)
    if root.tag != f"{{{EVENT_NS['e']}}}Event":
        raise ValueError("Expected one Windows Event XML record")

    system = root.find("e:System", EVENT_NS)
    provider = None if system is None else system.find("e:Provider", EVENT_NS)
    if (
        provider is None
        or provider.get("Name") != "Microsoft-Windows-Security-Auditing"
        or system.findtext("e:Channel", namespaces=EVENT_NS) != "Security"
        or system.findtext("e:EventID", namespaces=EVENT_NS) != "4725"
    ):
        raise ValueError("Expected Security event 4725 from Windows Security Auditing")

    target_sids = root.findall("e:EventData/e:Data[@Name='TargetSid']", EVENT_NS)
    if len(target_sids) != 1:
        raise ValueError("Expected exactly one TargetSid")

    computer = system.findtext("e:Computer", default="", namespaces=EVENT_NS)
    if not computer.isascii():
        raise ValueError("Event computer name must be ASCII")
    event = {
        "event_id": "4725",
        "source_host": computer.lower(),
        "target_sid": target_sids[0].text,
        "record_id": system.findtext("e:EventRecordID", namespaces=EVENT_NS),
    }
    if not valid_event(event):
        raise ValueError("Event has an invalid computer name, target SID, or record ID")
    return event


def load_inventory(path):
    data = read_json(path)
    if not isinstance(data, dict) or data.keys() != {"approved_sources", "identities"}:
        raise ValueError("Inventory must contain approved_sources and identities")
    sources = data["approved_sources"]
    if (
        not isinstance(sources, list)
        or not all(matches(HOST, source) for source in sources)
        or len(set(sources)) != len(sources)
    ):
        raise ValueError("Approved sources must be unique lowercase hostnames")

    if not isinstance(data["identities"], list):
        raise ValueError("Inventory identities must be a list")
    identities = {}
    user_ids = set()
    for row in data["identities"]:
        if not (
            isinstance(row, dict)
            and row.keys() == {"target_sid", "okta_user_id", "protected", "status"}
            and matches(SID, row["target_sid"])
            and matches(OKTA_ID, row["okta_user_id"])
            and type(row["protected"]) is bool
            and isinstance(row["status"], str)
            and row["status"]
        ):
            raise ValueError("Invalid identity mapping in inventory")
        if row["target_sid"] in identities or row["okta_user_id"] in user_ids:
            raise ValueError("Inventory must map each target SID and Okta user ID only once")
        identities[row["target_sid"]] = row
        user_ids.add(row["okta_user_id"])
    return set(sources), identities


def decision(action, reason):
    return {"decision": action, "reason": reason}


def evaluate(event, sources, identities):
    if not valid_event(event):
        return decision("invalid", "malformed_event")
    if event["event_id"] != "4725":
        return decision("ignored", "unsupported_event")
    if event["source_host"] not in sources:
        return decision("ignored", "unapproved_source")

    identity = identities.get(event["target_sid"])
    if identity is None:
        return decision("manual_review", "unmapped_identity")
    if identity["protected"]:
        return decision("manual_review", "protected_identity")

    status = identity["status"]
    if status == "ACTIVE":
        return decision("would_suspend", "active_identity")
    if status in {"SUSPENDED", "DEPROVISIONED"}:
        return decision("already_inactive", "inactive_identity")
    return decision("manual_review", "other_status")


def load_cases(path):
    cases = read_json(path)
    if not isinstance(cases, list) or not cases:
        raise ValueError("Casebook must be a nonempty JSON array")
    names = set()
    for case in cases:
        if not (
            isinstance(case, dict)
            and case.keys() == {"name", "input", "expected"}
            and matches(CASE_NAME, case["name"])
            and isinstance(case["expected"], dict)
            and case["expected"].keys() == {"decision", "reason"}
            and all(isinstance(value, str) and value for value in case["expected"].values())
        ):
            raise ValueError("Malformed casebook entry")
        if case["name"] in names:
            raise ValueError("Case names must be unique")
        names.add(case["name"])
    return cases


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    normalize = commands.add_parser("normalize", help="convert a Windows event XML file to JSON")
    normalize.add_argument("event", type=Path)

    replay = commands.add_parser("replay", help="run the casebook against the offline model")
    replay.add_argument("cases", type=Path)
    replay.add_argument("inventory", type=Path)

    request = commands.add_parser("request", help="print the HTTP request body for a named case")
    request.add_argument("cases", type=Path)
    request.add_argument("name")

    check = commands.add_parser("check", help="check a captured Workflows JSON response")
    check.add_argument("cases", type=Path)
    check.add_argument("name")
    check.add_argument("response", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "normalize":
            print(json.dumps(normalize_event(read_text(args.event)), indent=2))
            return 0

        cases = load_cases(args.cases)
        if args.command == "replay":
            sources, identities = load_inventory(args.inventory)
            failures = 0
            for case in cases:
                actual = evaluate(case["input"], sources, identities)
                passed = actual == case["expected"]
                failures += not passed
                print(f"{'PASS' if passed else 'FAIL'} {case['name']}")
            print(f"{len(cases) - failures}/{len(cases)} cases passed")
            return int(failures > 0)

        case = next((item for item in cases if item["name"] == args.name), None)
        if case is None:
            raise ValueError("Case name was not found")
        if args.command == "request":
            print(json.dumps({"payload": json.dumps(case["input"])}, indent=2))
            return 0

        passed = read_json(args.response) == case["expected"]
        print(f"{'PASS' if passed else 'FAIL'} {case['name']}")
        if not passed:
            print(f"Expected exactly {json.dumps(case['expected'])}", file=sys.stderr)
        return int(not passed)
    except (OSError, ValueError, RecursionError, ET.ParseError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
