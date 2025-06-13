import pytest

import desec.exceptions
import desec.utils


@pytest.mark.parametrize(
    "rtype, subname, records",
    [
        ("A", "", ["192.0.2.1"]),
        ("A", "", ["192.0.2.1", "192.0.2.2"]),
        ("AAAA", "", ["2001:db8:10::1"]),
        ("TXT", "test", ['"test"']),
        ("CNAME", "www", ["test-suite.test."]),
        ("MX", "", ["test-suite.test."]),
        ("NS", "", ["ns1.test-suite.test.", "ns2.test-suite.test."]),
    ],
)
def test_sanitize_records_valid(rtype, subname, records):
    """Test sanitize_records() with valid input.

    Assert that output is the unchanged input.
    """
    rrset = desec.utils.sanitize_records(rtype, subname, records)

    assert rrset == records


@pytest.mark.parametrize(
    "rtype, subname, records, expected",
    [
        ("TXT", "test", ["test"], ['"test"']),
        ("CNAME", "www", ["test-suite.test"], ["test-suite.test."]),
        ("MX", "", ["test-suite.test"], ["test-suite.test."]),
        (
            "NS",
            "",
            ["ns1.test-suite.test", "ns2.test-suite.test"],
            ["ns1.test-suite.test.", "ns2.test-suite.test."],
        ),
    ],
)
def test_sanitize_records_fixable(rtype, subname, records, expected):
    """Test sanitize_records() with fixable errors.

    Assert that the output is fixed.
    """
    rrset = desec.utils.sanitize_records(rtype, subname, records)

    assert rrset == expected


@pytest.mark.parametrize(
    "rtype, subname, records",
    [
        ("CNAME", "www", ["test-suite.test.", "prod-suite.test."]),
        ("CNAME", "", ["test-suite.test."]),
        ("NS", "*", ["ns1.test-suite.test", "ns2.test-suite.test"]),
        ("NS", "*.test", ["ns1.test-suite.test", "ns2.test-suite.test"]),
    ],
)
def test_sanitize_records_unfixable(rtype, subname, records):
    """Test sanitize_records() with unfixable errors.

    Assert that an appropriate exception is raised.
    """
    with pytest.raises(desec.exceptions.ParameterCheckError):
        desec.utils.sanitize_records(rtype, subname, records)
