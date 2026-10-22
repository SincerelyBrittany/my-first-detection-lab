"""Unit tests for the Sigma evaluator itself, so a passing rule test means the rule is right,
not that the matcher is too lenient."""

import pytest

from detectionlab.matcher import Rule


def rule(detection):
    return Rule(path=None, title="t", id="x", level="low", tags=[], logsource={}, detection=detection)


EVENT = {
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": "cmd.exe /c whoami",
    "EventID": 1,
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/a"},
}


def test_exact_match_is_case_insensitive():
    assert rule({"s": {"Image": r"c:\windows\system32\CMD.EXE"}, "condition": "s"}).matches(EVENT)


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("Image|endswith", r"\cmd.exe", True),
        ("Image|startswith", r"C:\Windows", True),
        ("CommandLine|contains", "WHOAMI", True),
        ("CommandLine|contains", "net user", False),
        ("CommandLine|re", r"/c\s+who", True),
    ],
)
def test_modifiers(key, value, expected):
    assert rule({"s": {key: value}, "condition": "s"}).matches(EVENT) is expected


def test_value_list_is_or_and_all_modifier_is_and():
    assert rule({"s": {"CommandLine|contains": ["nope", "whoami"]}, "condition": "s"}).matches(EVENT)
    assert not rule({"s": {"CommandLine|contains|all": ["nope", "whoami"]}, "condition": "s"}).matches(EVENT)
    assert rule({"s": {"CommandLine|contains|all": ["cmd", "whoami"]}, "condition": "s"}).matches(EVENT)


def test_selection_mapping_is_and_list_is_or():
    both = {"Image|endswith": "cmd.exe", "CommandLine|contains": "nope"}
    assert not rule({"s": both, "condition": "s"}).matches(EVENT)
    assert rule({"s": [both, {"EventID": 1}], "condition": "s"}).matches(EVENT)


def test_numbers_compare_as_strings():
    assert rule({"s": {"EventID": "1"}, "condition": "s"}).matches(EVENT)


def test_dotted_fields_and_exists():
    assert rule({"s": {"userIdentity.type": "IAMUser"}, "condition": "s"}).matches(EVENT)
    assert rule({"s": {"errorCode|exists": False}, "condition": "s"}).matches(EVENT)
    assert not rule({"s": {"errorCode|exists": True}, "condition": "s"}).matches(EVENT)
    assert not rule({"s": {"Missing.Field": "x"}, "condition": "s"}).matches(EVENT)


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("yes and not no", True),
        ("yes and no", False),
        ("no or yes", True),
        ("not (yes and no)", True),
        ("yes and (no or yes)", True),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("1 of them", True),
        ("all of them", False),
    ],
)
def test_conditions(condition, expected):
    detection = {
        "yes": {"EventID": 1},
        "no": {"EventID": 2},
        "sel_a": {"EventID": 1},
        "sel_b": {"EventID": 3},
        "condition": condition,
    }
    assert rule(detection).matches(EVENT) is expected


@pytest.mark.parametrize("condition", ["missing", "yes and", "(yes", "yes yes"])
def test_bad_conditions_raise(condition):
    with pytest.raises(ValueError):
        rule({"yes": {"EventID": 1}, "condition": condition}).matches(EVENT)
