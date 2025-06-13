import re

import pytest

import desec.exceptions


@pytest.mark.vcr
def test_new_domain(request, api_client, domain_name):
    """Test APIClient.new_domain() with valid parameters.

    Assert that the API confirms domain creation.
    """
    # Define a cleanup function to ensure the domain gets deleted even if the test fails.
    request.addfinalizer(lambda: api_client.delete_domain(domain_name))

    domain_info = api_client.new_domain(domain_name)

    assert domain_info["name"] == domain_name


@pytest.mark.vcr
def test_delete_domain(api_client, domain):
    """Test APIClient.delete_domain() with valid parameters.

    Assert that the API does not list the domain afterwards.
    """
    api_client.delete_domain(domain)

    domains = api_client.list_domains()
    assert domain not in [d["name"] for d in domains]


@pytest.mark.vcr
def test_list_domains(api_client, domain):
    """Test APIClient.list_domains().

    Assert that the API returns an existing domain.
    """
    domains = api_client.list_domains()

    assert domain in [d["name"] for d in domains]


@pytest.mark.vcr
def test_domain_info(api_client, domain):
    """Test APIClient.domain_info() with valid parameters.

    Assert that the API returns information about the given domain.
    """
    domain_info = api_client.domain_info(domain)

    assert domain_info["name"] == domain


@pytest.mark.vcr
def test_new_domain_invalid_name(api_client):
    """Test APIClient.new_domain() with invalid parameters.

    Assert that an appropriate exception is raised.
    """
    domain = "example.internal"
    with pytest.raises(desec.exceptions.ParameterError):
        api_client.new_domain(domain)


@pytest.mark.vcr
def test_domain_info_invalid(api_client):
    """Test APIClient.domain_info() with invalid parameters.

    Assert that an appropriate exception is raised.
    """
    domain = "not-a-valid-domain-for-this-account.test"
    with pytest.raises(desec.exceptions.NotFoundError):
        api_client.domain_info(domain)


@pytest.mark.vcr
def test_export_zonefile_domain(api_client, domain):
    """Test APIClient.export_zonefile_domain() with valid parameters.

    Assert that the API returns zonefile-like data for the given domain.
    """
    zonefile = api_client.export_zonefile_domain(domain)
    # Assert presence of a SOA record in RFC 1035 format.
    assert re.search(
        rf"^{domain}\.\s+\d+\s+IN\s+SOA\s+\S+\s+\S+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+$",
        zonefile,
        re.MULTILINE | re.ASCII,
    )
