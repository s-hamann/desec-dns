import desec


def test_parse_zone_file():
    """Test parse_zone_file() with valid input.

    Assert that the zone file is parsed correctly.
    """
    file = "tests/files/test-suite.test_valid.zone"
    domain = "test-suite.test"
    minimum_ttl = 3600
    correct_rrsets = [
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "MX",
            "records": ["10 mail.test-suite.test.", "20 mail2.test-suite.test."],
            "ttl": 86400,
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "A",
            "records": ["192.0.2.1"],
            "ttl": 3600,
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "AAAA",
            "records": ["2001:db8:10::1"],
            "ttl": 3600,
        },
        {
            "name": "www.test-suite.test.",
            "subname": "www",
            "type": "CNAME",
            "records": ["test-suite.test."],
            "ttl": 3600,
        },
        {
            "name": "mail.test-suite.test.",
            "subname": "mail",
            "type": "A",
            "records": ["192.0.2.2"],
            "ttl": 7200,
        },
        {
            "name": "mail2.test-suite.test.",
            "subname": "mail2",
            "type": "A",
            "records": ["192.0.2.3"],
            "ttl": 7200,
        },
    ]

    rrsets = desec.parse_zone_file(file, domain, minimum_ttl)

    assert len(rrsets) == len(correct_rrsets)
    for record in rrsets:
        assert record in correct_rrsets


def test_parse_zone_file_low_ttl():
    """Test parse_zone_file() with records that have a lower TTL than allowed.

    Assert that the zone file is parsed correctly and TTLs are corrected and annotated.
    """
    file = "tests/files/test-suite.test_valid.zone"
    domain = "test-suite.test"
    minimum_ttl = 7200
    correct_rrsets = [
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "MX",
            "records": ["10 mail.test-suite.test.", "20 mail2.test-suite.test."],
            "ttl": 86400,
        },
        {
            "error_msg": "TTL 3600 smaller than minimum of 7200 seconds.",
            "error_recovered": True,
            "name": ".test-suite.test.",
            "subname": "",
            "type": "A",
            "records": ["192.0.2.1"],
            "ttl": 7200,
        },
        {
            "error_msg": "TTL 3600 smaller than minimum of 7200 seconds.",
            "error_recovered": True,
            "name": ".test-suite.test.",
            "subname": "",
            "type": "AAAA",
            "records": ["2001:db8:10::1"],
            "ttl": 7200,
        },
        {
            "error_msg": "TTL 3600 smaller than minimum of 7200 seconds.",
            "error_recovered": True,
            "name": "www.test-suite.test.",
            "subname": "www",
            "type": "CNAME",
            "records": ["test-suite.test."],
            "ttl": 7200,
        },
        {
            "name": "mail.test-suite.test.",
            "subname": "mail",
            "type": "A",
            "records": ["192.0.2.2"],
            "ttl": 7200,
        },
        {
            "name": "mail2.test-suite.test.",
            "subname": "mail2",
            "type": "A",
            "records": ["192.0.2.3"],
            "ttl": 7200,
        },
    ]

    rrsets = desec.parse_zone_file(file, domain, minimum_ttl)

    assert len(rrsets) == len(correct_rrsets)
    for record in rrsets:
        assert record in correct_rrsets


def test_parse_zone_file_invalid():
    """Test parse_zone_file() with unsupported features.

    Assert that the zone file is parsed correctly and unsupported records are annotated.
    """
    file = "tests/files/test-suite.test_invalid.zone"
    domain = "test-suite.test"
    minimum_ttl = 3600
    correct_rrsets = [
        {
            "error_msg": "CNAME records in the zone apex are not allowed.",
            "error_recovered": False,
            "name": ".test-suite.test.",
            "records": ["prod-suite.test."],
            "subname": "",
            "ttl": 3600,
            "type": "CNAME",
        },
        {
            "name": "www.test-suite.test.",
            "records": ["test-suite.test."],
            "subname": "www",
            "ttl": 3600,
            "type": "CNAME",
        },
        {
            "name": "mail.test-suite.test.",
            "records": ["192.0.2.2"],
            "subname": "mail",
            "ttl": 7200,
            "type": "A",
        },
        {
            "name": "mail2.test-suite.test.",
            "records": ["192.0.2.3"],
            "subname": "mail2",
            "ttl": 7200,
            "type": "A",
        },
        {
            "error_msg": "Record type ISDN is not supported.",
            "error_recovered": False,
            "name": "call.test-suite.test.",
            "records": ['"493023125000"'],
            "subname": "call",
            "ttl": 3600,
            "type": "ISDN",
        },
    ]

    rrsets = desec.parse_zone_file(file, domain, minimum_ttl)

    assert len(rrsets) == len(correct_rrsets)
    for record in rrsets:
        assert record in correct_rrsets


def test_clear_errors_from_record_list_no_errors():
    """Test clear_errors_from_record_list() with input that does not have any errors.

    Assert that output is the unchanged input.
    """
    rrsets = [
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "MX",
            "records": ["10 mail.test-suite.test.", "20 mail2.test-suite.test."],
            "ttl": 86400,
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "A",
            "records": ["192.0.2.1"],
            "ttl": 3600,
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "AAAA",
            "records": ["2001:db8:10::1"],
            "ttl": 3600,
        },
        {
            "name": "www.test-suite.test.",
            "subname": "www",
            "type": "CNAME",
            "records": ["test-suite.test."],
            "ttl": 3600,
        },
        {
            "name": "mail.test-suite.test.",
            "subname": "mail",
            "type": "A",
            "records": ["192.0.2.2"],
            "ttl": 7200,
        },
        {
            "name": "mail2.test-suite.test.",
            "subname": "mail2",
            "type": "A",
            "records": ["192.0.2.3"],
            "ttl": 7200,
        },
    ]

    cleared_rrsets = desec.clear_errors_from_record_list(rrsets)

    assert cleared_rrsets == rrsets


def test_clear_errors_from_record_list_errors():
    """Test clear_errors_from_record_list() with input that does have errors.

    Assert that erroneous rrsets and error information are not present in the output.
    """
    rrsets = [
        {
            "error_msg": "CNAME records in the zone apex are not allowed.",
            "error_recovered": False,
            "name": ".test-suite.test.",
            "records": ["prod-suite.test."],
            "subname": "",
            "ttl": 3600,
            "type": "CNAME",
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "MX",
            "records": ["10 mail.test-suite.test.", "20 mail2.test-suite.test."],
            "ttl": 86400,
        },
        {
            "error_msg": "TTL 3600 smaller than minimum of 7200 seconds.",
            "error_recovered": True,
            "name": ".test-suite.test.",
            "subname": "",
            "type": "A",
            "records": ["192.0.2.1"],
            "ttl": 7200,
        },
        {
            "error_msg": "TTL 3600 smaller than minimum of 7200 seconds.",
            "error_recovered": True,
            "name": ".test-suite.test.",
            "subname": "",
            "type": "AAAA",
            "records": ["2001:db8:10::1"],
            "ttl": 7200,
        },
        {
            "error_msg": "TTL 3600 smaller than minimum of 7200 seconds.",
            "error_recovered": True,
            "name": "www.test-suite.test.",
            "subname": "www",
            "type": "CNAME",
            "records": ["test-suite.test."],
            "ttl": 7200,
        },
        {
            "name": "mail.test-suite.test.",
            "subname": "mail",
            "type": "A",
            "records": ["192.0.2.2"],
            "ttl": 7200,
        },
        {
            "name": "mail2.test-suite.test.",
            "subname": "mail2",
            "type": "A",
            "records": ["192.0.2.3"],
            "ttl": 7200,
        },
        {
            "error_msg": "Record type ISDN is not supported.",
            "error_recovered": False,
            "name": "call.test-suite.test.",
            "records": ['"493023125000"'],
            "subname": "call",
            "ttl": 3600,
            "type": "ISDN",
        },
    ]
    correct_rrsets = [
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "MX",
            "records": ["10 mail.test-suite.test.", "20 mail2.test-suite.test."],
            "ttl": 86400,
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "A",
            "records": ["192.0.2.1"],
            "ttl": 7200,
        },
        {
            "name": ".test-suite.test.",
            "subname": "",
            "type": "AAAA",
            "records": ["2001:db8:10::1"],
            "ttl": 7200,
        },
        {
            "name": "www.test-suite.test.",
            "subname": "www",
            "type": "CNAME",
            "records": ["test-suite.test."],
            "ttl": 7200,
        },
        {
            "name": "mail.test-suite.test.",
            "subname": "mail",
            "type": "A",
            "records": ["192.0.2.2"],
            "ttl": 7200,
        },
        {
            "name": "mail2.test-suite.test.",
            "subname": "mail2",
            "type": "A",
            "records": ["192.0.2.3"],
            "ttl": 7200,
        },
    ]

    cleared_rrsets = desec.clear_errors_from_record_list(rrsets)

    assert cleared_rrsets == correct_rrsets
