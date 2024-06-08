import pytest


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
