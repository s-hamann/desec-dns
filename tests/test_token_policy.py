import pytest

import desec.exceptions


@pytest.mark.vcr
def test_list_token_policies(api_client, new_token):
    """Test APIClient.list_token_policies() with valid parameters.

    Assert that the API returns an existing token policy.
    """
    token = new_token()
    default_policy = api_client.add_token_policy(token["id"])

    policies = api_client.list_token_policies(token["id"])

    assert len(policies) == 1
    assert policies[0] == default_policy


@pytest.mark.vcr
@pytest.mark.parametrize("policy_domain", [None, True], ids=[None, "domain"])
@pytest.mark.parametrize("policy_subname", [None, "test"])
@pytest.mark.parametrize("policy_rtype", [None, "A"])
@pytest.mark.parametrize("policy_perm_write", [True, False])
def test_add_token_policy(
    api_client, domain, new_token, policy_domain, policy_subname, policy_rtype, policy_perm_write
):
    """Test APIClient.add_token_policy() with valid parameters.

    Assert that the API confirms policy creation with the given parameters.
    """
    if policy_domain is True:
        # Since we can't use a fixture in a parameter value, we interpret the otherwise
        # invalid value `True` as "use `domain` fixture".
        policy_domain = domain
    token = new_token()

    if policy_domain is not None or policy_subname is not None or policy_rtype is not None:
        # The test case parameters do not specify a default policy, but we need to have
        # *some* default policy, before we can add other policies. Create one.
        api_client.add_token_policy(token["id"])

    policy = api_client.add_token_policy(
        token["id"], policy_domain, policy_subname, policy_rtype, policy_perm_write
    )

    assert "id" in policy
    assert policy["domain"] == policy_domain
    assert policy["subname"] == policy_subname
    assert policy["type"] == policy_rtype
    assert policy["perm_write"] == policy_perm_write


@pytest.mark.vcr
def test_add_token_policy_conflict(api_client, domain, new_token):
    """Test APIClient.add_token_policy() with two conflicting policies.

    Assert that an appropriate exception is raised.
    """
    token = new_token()
    # Add a default policy for the token.
    api_client.add_token_policy(token["id"])

    with pytest.raises(desec.exceptions.ConflictError):
        # Try adding another default policy. There can be only one.
        api_client.add_token_policy(token["id"])


@pytest.mark.vcr
@pytest.mark.parametrize("policy_domain", [False, None, True], ids=["keep", None, "domain"])
@pytest.mark.parametrize("policy_subname", [False, None, "test2"], ids=["keep", None, "test2"])
@pytest.mark.parametrize("policy_rtype", [False, None, "AAAA"], ids=["keep", None, "AAAA"])
@pytest.mark.parametrize("policy_perm_write", [None, True, False], ids=["keep", True, False])
@pytest.mark.uncollect_if(
    lambda policy_domain,
    policy_subname,
    policy_rtype,
    policy_perm_write,
    **kwargs: not policy_domain and policy_subname is None and policy_rtype is None
)
def test_modify_token_policy(
    api_client, domain, new_token, policy_domain, policy_subname, policy_rtype, policy_perm_write
):
    """Test APIClient.modify_token_policy() with valid parameters.

    Assert that the API confirms policy changes to the given parameters.
    """
    if policy_domain is True:
        # Since we can't use a fixture in a parameter value, we interpret the otherwise
        # invalid value `True` as "use `domain` fixture".
        policy_domain = domain
    initial_policy_domain = domain if policy_domain is None else None
    initial_policy_subname = "test"
    initial_policy_rtype = "A"
    initial_policy_perm_write = not policy_perm_write
    token = new_token()
    api_client.add_token_policy(token["id"])
    policy = api_client.add_token_policy(
        token["id"],
        initial_policy_domain,
        initial_policy_subname,
        initial_policy_rtype,
        initial_policy_perm_write,
    )

    modified_policy = api_client.modify_token_policy(
        token["id"], policy["id"], policy_domain, policy_subname, policy_rtype, policy_perm_write
    )

    # Assert that modified policy fields have the correct value and that unmodified policy
    # fields still have their initial value.
    assert modified_policy["id"] == policy["id"]
    if policy_domain is False:
        assert modified_policy["domain"] == initial_policy_domain
    else:
        assert modified_policy["domain"] == policy_domain
    if policy_subname is False:
        assert modified_policy["subname"] == initial_policy_subname
    else:
        assert modified_policy["subname"] == policy_subname
    if policy_rtype is False:
        assert modified_policy["type"] == initial_policy_rtype
    else:
        assert modified_policy["type"] == policy_rtype
    if policy_perm_write is None:
        assert modified_policy["perm_write"] == initial_policy_perm_write
    else:
        assert modified_policy["perm_write"] == policy_perm_write


@pytest.mark.vcr
def test_delete_token_policy(api_client, domain, new_token):
    """Test APIClient.delete_token_policy() with valid parameters.

    Assert that the API does not list the token policy afterwards.
    """
    token = new_token()
    default_policy = api_client.add_token_policy(token["id"])

    api_client.delete_token_policy(token["id"], default_policy["id"])

    policies = api_client.list_token_policies(token["id"])
    assert default_policy["id"] not in [p["id"] for p in policies]
