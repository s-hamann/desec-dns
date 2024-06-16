import pytest

import desec


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
