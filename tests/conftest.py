import os
import uuid

import pytest

import desec


@pytest.fixture(scope="session")
def vcr_config():
    """VCR.py configuration fixture."""

    def _skip_throttled_requests(response):
        if response["status"]["code"] == 429:
            return None
        return response

    return {
        # Replace/remove some headers in recodings.
        "filter_headers": [("authorization", "Token XXXXXXXX"), "user-agent", "connection"],
        # Do not record throttled requests.
        "before_record_response": _skip_throttled_requests,
    }


@pytest.fixture(scope="session")
def api_client():
    """Return an APIClient instance."""
    try:
        token = os.environ["DESEC_TOKEN"]
    except KeyError:
        token = None
    return desec.APIClient(token)


@pytest.fixture(scope="function")
def domain_name(disable_recording):
    """Return a domain name.

    The domain name is random when running against the live API and fixed when running
    against recorded mocks (or recording).
    """
    if disable_recording:
        # Running against the real API. Use a random domain.
        return str(uuid.uuid4()) + ".test"
    else:
        # Running against recorded mocks (or recording). Use a constant domain.
        return "test-suite.test"


def domain_scope(fixture_name, config):
    """Return the correct scope for the 'domain' fixture."""
    if config.getoption("--disable-recording"):
        # Running against the real API. Use the same domain for all tests.
        return "session"
    else:
        # Running against recorded mocks (or recording). Create and delete the domain for
        # each individual test. Because fixtures are only recorded with a function scope.
        # See https://github.com/kiwicom/pytest-recording/issues/76
        return "function"


@pytest.fixture(scope=domain_scope)
def domain(api_client, disable_recording):
    """Create a domain in the account and return its name."""
    # Note: This fixture intentionally does not use the domain_name fixture.
    # domain_name needs to be independent from domain to avoid interference.
    if disable_recording:
        # Running against the real API. Use a random domain.
        domain = str(uuid.uuid4()) + ".test"
    else:
        # Running against recorded mocks (or recording). Use a constant domain.
        domain = "test-suite.test"
    api_client.new_domain(domain)
    yield domain
    api_client.delete_domain(domain)
