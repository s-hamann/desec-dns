import time

import pytest

import desec


@pytest.mark.vcr
def test_invalid_authentication(request, api_client):
    """Test APIClient.query() with an invalid authentication token.

    Assert that an appropriate exception is raised.
    """
    # Define a cleanup function to ensure the authentication token of the api_client fixture
    # is reset.
    token_auth = api_client._token_auth
    request.addfinalizer(lambda: setattr(api_client, "_token_auth", token_auth))
    api_client._token_auth = desec.TokenAuth("invalid-token")

    with pytest.raises(desec.AuthenticationError):
        api_client.query("GET", f"{desec.API_BASE_URL}/domains/")


@pytest.mark.vcr
def test_invalid_authorization(request, api_client, new_token):
    """Test APIClient.query() with an authentication token with insufficient permissions.

    Assert that an appropriate exception is raised.
    """
    # Define a cleanup function to ensure the authentication token of the api_client fixture
    # is reset.
    token = new_token(manage_tokens=False)
    token_auth = api_client._token_auth
    request.addfinalizer(lambda: setattr(api_client, "_token_auth", token_auth))
    api_client._token_auth = desec.TokenAuth(token["token"])

    with pytest.raises(desec.TokenPermissionError):
        api_client.query("GET", f"{desec.API_BASE_URL}/auth/tokens/")


@pytest.mark.vcr
def test_pagination(request, api_client, domain):
    """Test APIClient.query() with pagination.

    Assert that paginated responses are merged and returned correctly.
    """
    rrsets = [
        {"type": "TXT", "subname": f"{i}.test", "records": [f'"pagination test {i}"'], "ttl": 3600}
        for i in range(0, 501)
    ]
    # Define a cleanup function to ensure the rrsets get deleted even if the test fails.
    request.addfinalizer(
        lambda: api_client.update_bulk_record(domain, [r | {"records": []} for r in rrsets])
    )
    # Add more than 500 RRsets to the domain.
    records = api_client.update_bulk_record(domain, rrsets, exclusive=True)

    response = api_client.query("GET", f"{desec.API_BASE_URL}/domains/{domain}/rrsets/")

    assert len(response) > 500
    for r in records:
        assert r in response


# Disable the before_record_response filter for this test since it prevents rate-limited
# requests from being recorded.
@pytest.mark.vcr(before_record_response=None)
def test_rate_limit_blocking(api_client, domain, new_record):
    """Test APIClient.query() with rate limiting in blocking mode.

    Assert that a throttled request returns the expected data.
    """
    # Set APIClient to blocking mode.
    api_client._retry_limit = 3
    # At the time of this writing, the rate limit for record writing operations is 2/s.
    # Therefore, the third request should be throttled. Others may be as well, depending on
    # previous tests in the same run.
    new_record("TXT", "test", ['"test1"'], 3600)
    api_client.change_record(domain, "TXT", "test", ['"test2"'], 3600)

    tic = time.perf_counter()
    record = api_client.query(
        "PATCH",
        f"{desec.API_BASE_URL}/domains/{domain}/rrsets/test.../TXT/",
        data={"records": ['"test3"']},
    )
    toc = time.perf_counter()

    assert toc - tic > 1
    assert record["records"] == ['"test3"']


# Disable the before_record_response filter for this test since it prevents rate-limited
# requests from being recorded.
@pytest.mark.vcr(before_record_response=None)
def test_rate_limit_non_blocking(request, api_client, domain, new_record):
    """Test APIClient.query() with rate limiting in non-blocking mode.

    Assert that an appropriate exception is raised for a throttled request
    """
    # Define a cleanup function to ensure the retry limit of the api_client fixture is
    # reset.
    retry_limit = api_client._retry_limit
    request.addfinalizer(lambda: setattr(api_client, "_retry_limit", retry_limit))

    # At the time of this writing, the rate limit for record writing operations is 2/s.
    # Therefore, the third request should be throttled. Others may be as well, depending on
    # previous tests in the same run.
    new_record("TXT", "test", ['"test1"'], 3600)
    api_client.change_record(domain, "TXT", "test", ['"test2"'], 3600)

    # Set APIClient to non-blocking mode.
    api_client._retry_limit = 0
    with pytest.raises(desec.RateLimitError):
        api_client.query(
            "PATCH",
            f"{desec.API_BASE_URL}/domains/{domain}/rrsets/test.../TXT/",
            data={"records": ['"test3"']},
        )
