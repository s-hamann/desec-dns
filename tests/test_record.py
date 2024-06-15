import pytest

import desec


@pytest.mark.vcr
@pytest.mark.parametrize("rtype", [None, "A"])
@pytest.mark.parametrize("subname", [None, "test"])
def test_get_records(api_client, domain, new_record, rtype, subname):
    """Test APIClient.get_records() with and without a filter that matches an RRset.

    Assert that the RRset is returned.
    """
    test_rtype = "A"
    test_subname = "test"
    r = new_record(test_rtype, test_subname, ["192.0.2.1"], 3600)

    records = api_client.get_records(domain, rtype, subname)

    assert len(records) >= 1
    assert r in records


@pytest.mark.vcr
@pytest.mark.parametrize(
    "rtype, subname",
    [
        (None, "negative-test"),
        ("A", "negative-test"),
        ("AAAA", None),
        ("AAAA", "test"),
        ("AAAA", "negative-test"),
    ],
)
def test_get_records_no_match(api_client, domain, new_record, rtype, subname):
    """Test APIClient.get_records() with a filter that does not match an RRset.

    Assert that the RRset is not returned.
    """
    test_rtype = "A"
    test_subname = "test"
    r = new_record(test_rtype, test_subname, ["192.0.2.1"], 3600)

    records = api_client.get_records(domain, rtype, subname)

    assert r not in records


@pytest.mark.vcr
@pytest.mark.parametrize("subname", ["", "test"])
def test_add_record(api_client, domain, subname):
    """Test APIClient.add_record() with valid parameters.

    Assert that the API confirms RRset creation.
    """
    record = api_client.add_record(domain, "A", subname, ["192.0.2.1"], 3600)

    assert record["type"] == "A"
    assert record["subname"] == subname
    assert record["domain"] == domain
    assert record["records"] == ["192.0.2.1"]
    assert record["ttl"] == 3600


@pytest.mark.vcr
def test_add_record_invalid_type(api_client, domain):
    """Test APIClient.add_record() with invalid parameters.

    Assert that an appropriate exception is raised.
    """
    with pytest.raises(desec.ParameterError):
        api_client.add_record(domain, "INVALID", "", "test-data", 3600)


@pytest.mark.vcr
def test_update_bulk_records_non_exclusive(request, api_client, domain, new_record):
    """Test APIClient.update_bulk_record() with valid parameters in non-exclusive mode.

    Assert that the API confirms RRset updates and that existing RRsets are kept or updated,
    as appropriate.
    """
    r1 = new_record("A", "", ["192.0.2.1"], 3600)
    r2 = new_record("A", "test2", ["192.0.2.1"], 3600)
    rrsets = [
        {"type": "A", "subname": "test", "records": ["192.0.2.1"], "ttl": 3600},
        {"type": "AAAA", "subname": "test", "records": ["2001:BD8::1"], "ttl": 7200},
        {"type": "A", "subname": "", "records": ["192.0.2.2"], "ttl": 10800},
    ]
    # Define a cleanup function to ensure the rrsets get deleted even if the test fails.
    request.addfinalizer(
        lambda: api_client.update_bulk_record(domain, [r | {"records": []} for r in rrsets])
    )

    records = api_client.update_bulk_record(domain, rrsets, exclusive=False)

    for rrset in rrsets:
        updated_rrset = next(
            (
                r
                for r in records
                if r["type"] == rrset["type"] and r["subname"] == rrset["subname"]
            ),
            None,
        )
        for key in rrset:
            if isinstance(rrset[key], list):
                # Do order-insenstive comparison for lists (records).
                if key == "records" and rrset["type"] == "AAAA":
                    # Do case-insensitive comparison for IPv6 addresses.
                    assert set(map(str.lower, rrset[key])) == set(
                        map(str.lower, updated_rrset[key])
                    )
                else:
                    assert set(rrset[key]) == set(updated_rrset[key])
            else:
                assert rrset[key] == updated_rrset[key]
    records = api_client.get_records(domain)
    assert r1 not in records
    assert r2 in records


@pytest.mark.vcr
def test_update_bulk_records_exclusive(request, api_client, domain, new_record):
    """Test APIClient.update_bulk_record() with valid parameters in exclusive mode.

    Assert that the API confirms RRset updates and that existing RRsets are removed.
    """
    r1 = new_record("A", "", ["192.0.2.1"], 3600)
    r2 = new_record("A", "test2", ["192.0.2.1"], 3600)
    rrsets = [
        {"type": "A", "subname": "test", "records": ["192.0.2.1"], "ttl": 3600},
        {"type": "AAAA", "subname": "test", "records": ["2001:BD8::1"], "ttl": 7200},
        {"type": "A", "subname": "", "records": ["192.0.2.2"], "ttl": 10800},
    ]
    # Define a cleanup function to ensure the rrsets get deleted even if the test fails.
    request.addfinalizer(
        lambda: api_client.update_bulk_record(domain, [r | {"records": []} for r in rrsets])
    )

    records = api_client.update_bulk_record(domain, rrsets, exclusive=True)

    for rrset in rrsets:
        updated_rrset = next(
            (
                r
                for r in records
                if r["type"] == rrset["type"] and r["subname"] == rrset["subname"]
            ),
            None,
        )
        for key in rrset:
            if isinstance(rrset[key], list):
                # Do order-insenstive comparison for lists (records).
                if key == "records" and rrset["type"] == "AAAA":
                    # Do case-insensitive comparison for IPv6 addresses.
                    assert set(map(str.lower, rrset[key])) == set(
                        map(str.lower, updated_rrset[key])
                    )
                else:
                    assert set(rrset[key]) == set(updated_rrset[key])
            else:
                assert rrset[key] == updated_rrset[key]
    records = api_client.get_records(domain)
    assert r1 not in records
    assert r2 not in records


@pytest.mark.vcr
def test_change_record_rdata(api_client, domain, new_record):
    """Test APIClient.change_record() with valid parameters, changing the record data.

    Assert that the API confirms the change.
    """
    original_rdata = ["192.0.2.1"]
    new_rdata = ["192.0.2.2"]
    original_ttl = 3600
    new_record("A", "test", original_rdata, original_ttl)

    record = api_client.change_record(domain, "A", "test", new_rdata)

    assert record["type"] == "A"
    assert record["records"] == new_rdata
    assert record["ttl"] == original_ttl


@pytest.mark.vcr
def test_change_record_ttl(api_client, domain, new_record):
    """Test APIClient.change_record() with valid parameters, changing the TTL.

    Assert that the API confirms the change.
    """
    original_rdata = ["192.0.2.1"]
    original_ttl = 3600
    new_ttl = 7200
    new_record("A", "test", original_rdata, original_ttl)

    record = api_client.change_record(domain=domain, rtype="A", subname="test", ttl=new_ttl)

    assert record["type"] == "A"
    assert record["records"] == original_rdata
    assert record["ttl"] == new_ttl


@pytest.mark.vcr
def test_change_record_rdata_ttl(api_client, domain, new_record):
    """Test APIClient.change_record() with valid parameters, changing record data and TTL.

    Assert that the API confirms the change.
    """
    original_rdata = ["192.0.2.1"]
    new_rdata = ["192.0.2.2"]
    original_ttl = 3600
    new_ttl = 7200
    new_record("A", "test", original_rdata, original_ttl)

    record = api_client.change_record(domain, "A", "test", new_rdata, new_ttl)

    assert record["type"] == "A"
    assert record["records"] == new_rdata
    assert record["ttl"] == new_ttl


@pytest.mark.vcr
def test_change_record_missing(api_client, domain):
    """Test APIClient.change_record() with invalid parameters.

    Assert that an appropriate exception is raised.
    """
    with pytest.raises(desec.NotFoundError):
        api_client.change_record(domain, "A", "not-an-existing-subname", ttl=3600)


@pytest.mark.vcr
def test_delete_record_full(api_client, domain, new_record):
    """Test APIClient.delete_record() with valid parameters, deleting a full RRset.

    Assert that the API does not list the RRset afterwards.
    """
    rdata = ["192.0.2.1", "192.0.2.2"]
    new_record("A", "test", rdata, 3600)

    api_client.delete_record(domain, "A", "test")

    records = api_client.get_records(domain, "A", "test")
    assert len(records) == 0


@pytest.mark.vcr
def test_delete_record_partial(api_client, domain, new_record):
    """Test APIClient.delete_record() with valid parameters, deleting only a single record.

    Assert that the API lists the remaining record afterwards.
    """
    rdata = ["192.0.2.1", "192.0.2.2"]
    new_record("A", "test", rdata, 3600)

    api_client.delete_record(domain, "A", "test", [rdata[0]])

    records = api_client.get_records(domain, "A", "test")
    assert len(records) == 1
    assert records[0]["records"] == [rdata[1]]


@pytest.mark.vcr
def test_delete_record_partial_missing(api_client, domain, new_record):
    """Test APIClient.delete_record() with valid parameters on a non-existing RRset.

    Assert that the API does not list the RRset afterwards.
    """
    api_client.delete_record(domain, "A", "not-an-existing-subname", ["192.0.2.1"])

    records = api_client.get_records(domain, "A", "not-an-existing-subname")
    assert len(records) == 0


@pytest.mark.vcr
def test_update_record_existing(api_client, domain, new_record):
    """Test APIClient.update_record() with valid parameters on an existing RRset.

    Assert that the API confirms the change and that the TTL is unchanged.
    """
    new_record("A", "test", ["192.0.2.1"], 3600)

    record = api_client.update_record(domain, "A", "test", ["192.0.2.2"], 7200)

    assert "192.0.2.1" in record["records"]
    assert "192.0.2.2" in record["records"]
    assert record["ttl"] == 3600


@pytest.mark.vcr
def test_update_record_existing_no_ttl(api_client, domain, new_record):
    """Test APIClient.update_record() with valid parameters on an existing RRset.

    Assert that the API confirms the change.
    """
    new_record("A", "test", ["192.0.2.1"], 3600)

    record = api_client.update_record(domain, "A", "test", ["192.0.2.2"])

    assert "192.0.2.1" in record["records"]
    assert "192.0.2.2" in record["records"]
    assert record["ttl"] == 3600


@pytest.mark.vcr
def test_update_record_new(api_client, domain):
    """Test APIClient.update_record() with valid parameters on a non-existing RRset.

    Assert that the API confirms the change.
    """
    record = api_client.update_record(domain, "A", "test", ["192.0.2.2"], 7200)

    assert record["records"] == ["192.0.2.2"]
    assert record["ttl"] == 7200


@pytest.mark.vcr
def test_update_record_new_no_ttl(api_client, domain):
    """Test APIClient.update_record() without the `ttl` parameter on a non-existing RRset.

    Assert that an appropriate exception is raised.
    """
    with pytest.raises(desec.ParameterCheckError):
        api_client.update_record(domain, "A", "test", ["192.0.2.1"])
