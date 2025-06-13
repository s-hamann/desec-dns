import pytest

import desec.exceptions


@pytest.mark.vcr
def test_not_found_error(api_client):
    """Test APIError.__str__() for a response containing an error with the `detail` key.

    Assert that the formatted exception contains the error message returned by the API.
    """
    domain = "not-a-valid-domain-for-this-account.test"

    with pytest.raises(desec.exceptions.NotFoundError) as excinfo:
        api_client.domain_info(domain)

    assert "Not found." in str(excinfo.value)


@pytest.mark.vcr
def test_not_found_error_non_json(api_client):
    """Test APIError.__str__() for a response that is not JSON-formatted.

    Assert that the formatted exception contains the error message returned by the API.
    """
    domain = "not-a-valid-domain-for-this-account.test"

    with pytest.raises(desec.exceptions.NotFoundError) as excinfo:
        api_client.export_zonefile_domain(domain)

    assert "Not found." in str(excinfo.value)


@pytest.mark.vcr
def test_parameter_error_single(api_client, domain):
    """Test APIError.__str__() for a response containing a single error.

    Assert that the formatted exception contains the error message returned by the API.
    """

    with pytest.raises(desec.exceptions.ParameterError) as excinfo:
        api_client.add_record(domain, "TEST", "test", ["test"], 1)

    assert "The TEST RR set type is currently unsupported." in str(excinfo.value)
    assert "Ensure this value is greater than or equal to 3600." in str(excinfo.value)


@pytest.mark.vcr
def test_parameter_error_list(api_client, domain):
    """Test APIError.__str__() for a response containing multiple errors.

    Assert that the formatted exception contains all error messages returned by the API.
    """
    rrsets = [
        {"type": "A", "subname": "test", "records": ["test"], "ttl": 3600},
        {"type": "AAAA", "subname": "test", "records": ["test"], "ttl": 7200},
        {"type": "TEST", "subname": "test", "records": ["test"], "ttl": 1},
    ]

    with pytest.raises(desec.exceptions.ParameterError) as excinfo:
        api_client.update_bulk_record(domain, rrsets, exclusive=False)

    assert "Record content for type A malformed: Text input is malformed." in str(excinfo.value)
    assert "Record content for type AAAA malformed: Text input is malformed." in str(excinfo.value)
    assert "The TEST RR set type is currently unsupported." in str(excinfo.value)
    assert "Ensure this value is greater than or equal to 3600." in str(excinfo.value)
