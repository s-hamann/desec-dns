import os
import uuid

import pytest

import desec.api


def pytest_configure(config):
    """Pytest configuration."""
    config.addinivalue_line(
        # Parametrized test functions may produce undesired test cases (because some
        # combinations do not make any sense). Decorate them with
        # @pytest.mark.uncollect_if(...) or @pytest.mark.uncollect_if(func=...)
        # to completely ignore certain combinations, based on the return value of the
        # (lambda) function parameter to `uncollect_if`.
        "markers",
        "uncollect_if(func): completely ignore certain parametrization combinations",
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):
    """Implementation of the `uncollect_if` marker."""
    outcome = yield None
    report = outcome.get_result()
    if report:
        kept = []
        for item in report.result:
            if isinstance(item, pytest.Function):
                m = item.get_closest_marker("uncollect_if")
                if m:
                    try:
                        func = m.kwargs["func"]
                    except KeyError:
                        func = m.args[0]
                    if func(**item.callspec.params):
                        continue
            kept.append(item)
        report.result = kept
        outcome.force_result(report)


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
    return desec.api.APIClient(token)


@pytest.fixture(scope="function")
def new_token(api_client):
    """Return a new API token.

    All tokens created by this fixture are automatically deleted after the test.
    """
    created_tokens = []

    def _new_token(**kwargs):
        new_token = api_client.create_token(**kwargs)
        created_tokens.append(new_token["id"])
        return new_token

    yield _new_token

    for t in created_tokens:
        api_client.delete_token(t)


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


@pytest.fixture(scope="function")
def new_record(api_client, domain, request):
    """Create an RRset in the domain and return it.

    All RRsets created by this fixture are automatically deleted after the test.

    Args:
        rtype: The type of the new record.
        subname: The subname of the new record.
        records: The content of the new record.
        ttl: The TTL of the new record.
    """
    created_records = []

    def _new_record(rtype, subname, records, ttl):
        new_record = api_client.add_record(domain, rtype, subname, records, ttl)
        created_records.append((rtype, subname, records, ttl))
        return new_record

    yield _new_record

    for r in created_records:
        api_client.delete_record(domain, r[0], r[1])
