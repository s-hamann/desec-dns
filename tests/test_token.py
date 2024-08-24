import pytest


@pytest.mark.vcr
def test_list_tokens(api_client):
    """Test APIClient.list_tokens().

    Assert that the API returns at least one token.
    """
    tokens = api_client.list_tokens()

    assert len(tokens) >= 1
    assert "id" in tokens[0]


@pytest.mark.vcr
@pytest.mark.parametrize(
    "new_token_params",
    [
        {},
        {"name": "test-suite"},
        {"manage_tokens": True},
        {"manage_tokens": False},
        {"allowed_subnets": ["192.0.2.0/24", "2001:db8::/32"]},
        {"allowed_subnets": None},
    ],
    ids=[
        "simple",
        "named",
        "perm_manage_tokens",
        "no_perm_manage_tokens",
        "restricted_subnets",
        "all_subnets",
    ],
)
def test_create_token(request, api_client, new_token_params):
    """Test APIClient.create_token() with valid parameters.

    Assert that the API returns a token according to the given parameters.
    """
    # Define a cleanup function to ensure the token gets deleted even if the test fails.
    old_token_ids = [t["id"] for t in api_client.list_tokens()]

    def _cleanup_tokens():
        current_token_ids = [t["id"] for t in api_client.list_tokens()]
        for t in current_token_ids:
            if t not in old_token_ids:
                api_client.delete_token(t)

    request.addfinalizer(_cleanup_tokens)

    # Actual test step.
    token = api_client.create_token(**new_token_params)

    # Validation.
    assert "id" in token
    assert "token" in token
    # Assert that requested fields have the correct value.
    for key, value in new_token_params.items():
        if key == "manage_tokens":
            key = "perm_manage_tokens"
        elif key == "allowed_subnets" and value is None:
            value = ["0.0.0.0/0", "::/0"]
        assert token[key] == value


@pytest.mark.vcr
@pytest.mark.parametrize(
    "changed_token_params",
    [{}, {"name": "test-suite"}, {"manage_tokens": True}, {"manage_tokens": False}],
    ids=["simple", "named", "perm_manage_tokens", "no_perm_manage_tokens"],
)
def test_modify_token(api_client, new_token, changed_token_params):
    """Test APIClient.modify_token() with valid parameters.

    Assert that the API returns a token according to the given parameters.
    """
    new_token_params = {"manage_tokens": not changed_token_params.get("manage_tokens", True)}
    token = new_token(**new_token_params)

    modified_token = api_client.modify_token(token["id"], **changed_token_params)

    assert "id" in modified_token
    # Assert that modified fields have the correct value.
    for key, value in changed_token_params.items():
        if key == "manage_tokens":
            key = "perm_manage_tokens"
        assert modified_token[key] == value
    # Assert that fields that were not modified did not change.
    for key in modified_token:
        if key not in [
            "perm_manage_tokens" if k == "manage_tokens" else k for k in changed_token_params
        ]:
            assert token[key] == modified_token[key]


@pytest.mark.vcr
def test_delete_token(api_client):
    """Test APIClient.delete_token() with valid parameters.

    Assert that the API does not list the token afterwards.
    """
    token = api_client.create_token()

    api_client.delete_token(token["id"])

    tokens = api_client.list_tokens()
    assert token["id"] not in [t["id"] for t in tokens]
