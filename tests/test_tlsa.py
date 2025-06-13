import pytest

import desec.exceptions
import desec.tlsa


@pytest.mark.parametrize("value", ["PKIX-TA", "PKIX-EE", "DANE-TA", "DANE-EE", 0, 1, 2, 3])
def test_tlsausage(value):
    """Test value mapping and comparisons of TLSAUsage objects.

    Assert correct comparison.
    """
    tlsa_usage_map = {
        "PKIX-TA": 0,
        "PKIX-EE": 1,
        "DANE-TA": 2,
        "DANE-EE": 3,
        0: "PKIX-TA",
        1: "PKIX-EE",
        2: "DANE-TA",
        3: "DANE-EE",
    }

    usage = desec.tlsa.TLSAUsage(value)

    assert tlsa_usage_map[repr(usage)] == int(usage)
    assert usage == repr(usage)
    assert usage == int(usage)
    assert usage == desec.tlsa.TLSAUsage(tlsa_usage_map[value])


@pytest.mark.parametrize("value", ["CERT", "SPKI", 0, 1])
def test_tlsaselector(value):
    """Test value mapping and comparisons of TLSASelector objects.

    Assert correct comparison.
    """
    tlsa_selector_map = {
        "CERT": 0,
        "SPKI": 1,
        0: "CERT",
        1: "SPKI",
    }

    selector = desec.tlsa.TLSASelector(value)

    assert tlsa_selector_map[repr(selector)] == int(selector)
    assert selector == repr(selector)
    assert selector == int(selector)
    assert selector == desec.tlsa.TLSASelector(tlsa_selector_map[value])


@pytest.mark.parametrize("value", ["FULL", "SHA2-256", "SHA2-512", 0, 1, 2])
def test_tlsamatchtype(value):
    """Test value mapping and comparisons of TLSAMatchType objects.

    Assert correct comparison.
    """
    tlsa_matchtype_map = {
        "FULL": 0,
        "SHA2-256": 1,
        "SHA2-512": 2,
        0: "FULL",
        1: "SHA2-256",
        2: "SHA2-512",
    }

    matchtype = desec.tlsa.TLSAMatchType(value)

    assert tlsa_matchtype_map[repr(matchtype)] == int(matchtype)
    assert matchtype == repr(matchtype)
    assert matchtype == int(matchtype)
    assert matchtype == desec.tlsa.TLSAMatchType(tlsa_matchtype_map[value])


@pytest.mark.parametrize("cert_format", ["PEM", "DER"])
@pytest.mark.parametrize("usage", ["PKIX-EE", "DANE-EE"])
@pytest.mark.parametrize("selector", ["CERT", "SPKI"])
@pytest.mark.parametrize(
    "match_type",
    ["FULL", "SHA2-256", "SHA2-512"],
)
@pytest.mark.parametrize("check", [True, False], ids=["check", "no-check"])
@pytest.mark.parametrize("cert_domain", [None, "test-suite.test"])
def test_tlsa_record(cert_format, usage, selector, match_type, check, cert_domain):
    """Test tlsa_record() with valid input.

    Assert that the correct TLSA record data is returned.
    """
    # Test certificate file.
    if cert_format == "PEM":
        file = "tests/files/test_tlsa_record.pem"
    elif cert_format == "DER":
        file = "tests/files/test_tlsa_record.der"
    subname = ""
    # Correct binary data for the test certificate, indexed by the tuple of selector and
    # match type.
    hex_data_map = {
        # Full certificate.
        (0, 0): "3082034b30820233a003020102020101300d06092a864886f70d01010b050030"
        "40311f301d060355040a0c1648696768204173737572616e6365205465737420"
        "4341311d301b06035504030c145465737420434120476c6f62616c2054727573"
        "74301e170d3730303130313030303030305a170d333830313139303331343037"
        "5a301a3118301606035504030c0f746573742d73756974652e74657374308201"
        "22300d06092a864886f70d01010105000382010f003082010a0282010100b8b9"
        "494f035bf1f489888829d02eee2dbfa8f8acf0340e3051798fa713ad7f048a33"
        "82452abf19719e8bd06e889899c6199cef34786e0c96f9a393e3034b014e8b67"
        "4d66e8072a1f2bc973b29dc3cfda8d1e93ab3b58b5ec5c822d7fc54fce033d48"
        "e8bd6b0bc0db4a2bfb30880055d84e1e41db32af4fa1c72e8c098c7c8fcdc0f3"
        "3ae6506ee4b6b0b57de75e146617a375cd7f700228b7bacef0e6cc6b8e69908a"
        "4afcd0e93486bb354b8f4fc45aeaba2bb518ea7175c22cf4be412cb8435f1f79"
        "ec23e7bbe7bade41cc92ebfb94fa93a5d8c226a456787252769ec894eccef293"
        "6d63688ada1b2a8514c398786f41e104686673cdb3cd054765a83ee9444d0203"
        "010001a376307430090603551d1304023000301d0603551d0e04160414f3ac0e"
        "efce32cabaa98c461163b92d31b1181357301f0603551d23041830168014b5d3"
        "52b229ff9a9861ce3748d40ff3cb409e07b5300b0603551d0f0404030203a830"
        "1a0603551d1104133011820f746573742d73756974652e74657374300d06092a"
        "864886f70d01010b05000382010100ac25d9423b61f3b8a6d0780e9ccec0d2f4"
        "8eb25670f5b4faafa5e2b95891d6aa293320f2c4653a5a7e82d6172a6fc696bb"
        "6b604fc1dd20035eb5ac7517092f4f0a1895ded3edc12960b7301c385978ccb2"
        "927572046f559386248b0f981b42910b852f66946215637c88b9f9e71ef8bdb8"
        "a92cf66c9c0d2cfcb1c81a599afb79847bc1cac78a03d3b8b942a9af5220a12b"
        "ad81302a027b494742025e7d4049a19b1dac546c97027c2dc1eb9e9f1d29ab4e"
        "a38b78695ff9a0dd60f1f9218ca9492ad7d51f63a3235560055df6aa596cb490"
        "6e345c00198f14a27a76a758c51f8cbbde88f48568517814bb17f81d3a5cad70"
        "e4d573436074e76e3950eee4430139",
        # Full public key.
        (1, 0): "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
        "00b8b9494f035bf1f489888829d02eee2dbfa8f8acf0340e3051798fa713ad7f"
        "048a3382452abf19719e8bd06e889899c6199cef34786e0c96f9a393e3034b01"
        "4e8b674d66e8072a1f2bc973b29dc3cfda8d1e93ab3b58b5ec5c822d7fc54fce"
        "033d48e8bd6b0bc0db4a2bfb30880055d84e1e41db32af4fa1c72e8c098c7c8f"
        "cdc0f33ae6506ee4b6b0b57de75e146617a375cd7f700228b7bacef0e6cc6b8e"
        "69908a4afcd0e93486bb354b8f4fc45aeaba2bb518ea7175c22cf4be412cb843"
        "5f1f79ec23e7bbe7bade41cc92ebfb94fa93a5d8c226a456787252769ec894ec"
        "cef2936d63688ada1b2a8514c398786f41e104686673cdb3cd054765a83ee944"
        "4d0203010001",
        # SHA-256 of certificate.
        (0, 1): "2455cc72c422f74b1001a853a87242e4e35660aa2caf76a80de1bb59b8ba0248",
        # SHA-256 of public key.
        (1, 1): "049a3787ec713babcef0abf584bea25fe0a85cebae49e42a7285da0597c31e1e",
        # SHA-512 of certificate.
        (0, 2): "700c1cf61ba3a62adfd11d6f205137946fd68d499cdca8ace3161066a7dd82b6"
        "fa7dc9e1665989327e97a24cd45430f7f18b05c9acf31beed7f9bff9b5d0c22a",
        # SHA-512 of public key.
        (1, 2): "bc0e48408f40dca927c69750442f31a372b82c78596601c49b969f6549640793"
        "61fb78fab229df80d65e48e6f4b187be8ce2577414ae018b08ee7a8c0a8049b1",
    }

    usage = desec.tlsa.TLSAUsage(usage)
    selector = desec.tlsa.TLSASelector(selector)
    match_type = desec.tlsa.TLSAMatchType(match_type)

    rdata = desec.tlsa.tlsa_record(file, usage, selector, match_type, check, subname, cert_domain)

    assert (
        rdata
        == f"{int(usage)} {int(selector)} {int(match_type)} {hex_data_map[(int(selector), int(match_type))]}"
    )


def test_tlsa_record_expired_check():
    """Test tlsa_record() with an expired certificate in checking mode.

    Assert that an appropriate exception is raised.
    """
    # Test certificate file.
    file = "tests/files/test_tlsa_record_expired.pem"
    subname = ""
    cert_domain = "test-suite.test"

    usage = desec.tlsa.TLSAUsage(3)
    selector = desec.tlsa.TLSASelector(0)
    match_type = desec.tlsa.TLSAMatchType(1)

    with pytest.raises(desec.exceptions.TLSACheckError):
        desec.tlsa.tlsa_record(
            file,
            usage,
            selector,
            match_type,
            check=True,
            subname=subname,
            domain=cert_domain,
        )


def test_tlsa_record_expired_nocheck():
    """Test tlsa_record() with an expired certificate in non-checking mode.

    Assert that the correct TLSA record data is returned.
    """
    # Test certificate file.
    file = "tests/files/test_tlsa_record_expired.pem"
    subname = ""
    cert_domain = "test-suite.test"

    usage = desec.tlsa.TLSAUsage(3)
    selector = desec.tlsa.TLSASelector(0)
    match_type = desec.tlsa.TLSAMatchType(1)

    rdata = desec.tlsa.tlsa_record(
        file,
        usage,
        selector,
        match_type,
        check=False,
        subname=subname,
        domain=cert_domain,
    )

    assert rdata == "3 0 1 e716e31bc1957fa400d170b111fb6de651262ad9bb6d5dccc53b87c34988abfb"


@pytest.mark.parametrize(
    "subname, cert_domain", [("", "not-test-suite.test"), ("test", "test-suite.test")]
)
def test_tlsa_record_wrong_name_check(subname, cert_domain):
    """Test tlsa_record() with a certificate for another host name in checking mode.

    Assert that an appropriate exception is raised.
    """
    # Test certificate file.
    file = "tests/files/test_tlsa_record.pem"

    usage = desec.tlsa.TLSAUsage(3)
    selector = desec.tlsa.TLSASelector(0)
    match_type = desec.tlsa.TLSAMatchType(1)

    with pytest.raises(desec.exceptions.TLSACheckError):
        desec.tlsa.tlsa_record(
            file,
            usage,
            selector,
            match_type,
            check=True,
            subname=subname,
            domain=cert_domain,
        )


@pytest.mark.parametrize(
    "subname, cert_domain", [("", "not-test-suite.test"), ("test", "test-suite.test")]
)
def test_tlsa_record_wrong_name_nocheck(subname, cert_domain):
    """Test tlsa_record() with a certificate for another host name in non-checking mode.

    Assert that the correct TLSA record data is returned.
    """
    # Test certificate file.
    file = "tests/files/test_tlsa_record.pem"

    usage = desec.tlsa.TLSAUsage(3)
    selector = desec.tlsa.TLSASelector(0)
    match_type = desec.tlsa.TLSAMatchType(1)

    rdata = desec.tlsa.tlsa_record(
        file,
        usage,
        selector,
        match_type,
        check=False,
        subname=subname,
        domain=cert_domain,
    )

    assert rdata == "3 0 1 2455cc72c422f74b1001a853a87242e4e35660aa2caf76a80de1bb59b8ba0248"


@pytest.mark.parametrize("usage", ["PKIX-TA", "DANE-TA"])
def test_tlsa_record_wrong_usage_check(usage):
    """Test tlsa_record() with an incorrect TLSA usage field in checking mode.

    Assert that an appropriate exception is raised.
    """
    # Test certificate file.
    file = "tests/files/test_tlsa_record.pem"
    subname = ""
    cert_domain = "test-suite.test"

    usage = desec.tlsa.TLSAUsage(usage)
    selector = desec.tlsa.TLSASelector(0)
    match_type = desec.tlsa.TLSAMatchType(1)

    with pytest.raises(desec.exceptions.TLSACheckError):
        desec.tlsa.tlsa_record(
            file,
            usage,
            selector,
            match_type,
            check=True,
            subname=subname,
            domain=cert_domain,
        )


@pytest.mark.parametrize("usage", ["PKIX-TA", "DANE-TA"])
def test_tlsa_record_wrong_usage_nocheck(usage):
    """Test tlsa_record() with an incorrect TLSA usage field in non-checking mode.

    Assert that the correct TLSA record data is returned.
    """
    # Test certificate file.
    file = "tests/files/test_tlsa_record.pem"
    subname = ""
    cert_domain = "test-suite.test"

    usage = desec.tlsa.TLSAUsage(usage)
    selector = desec.tlsa.TLSASelector(0)
    match_type = desec.tlsa.TLSAMatchType(1)

    rdata = desec.tlsa.tlsa_record(
        file,
        usage,
        selector,
        match_type,
        check=False,
        subname=subname,
        domain=cert_domain,
    )

    assert (
        rdata
        == f"{int(usage)} 0 1 2455cc72c422f74b1001a853a87242e4e35660aa2caf76a80de1bb59b8ba0248"
    )
