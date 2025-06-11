"""desec.io API client.

This submodule handles interaction with the deSEC DNS management API, i.e. authentication
and management of domains, DNS record sets and authentication tokens.
"""

from __future__ import annotations

import logging
import re
import time
import typing as t

import requests

import desec.exceptions
import desec.types

API_BASE_URL = "https://desec.io/api/v1"


class TokenAuth(requests.auth.AuthBase):
    """Token-based authentication for requests.

    Custom authentication hook for requests to handle token-based authentication as
    required by the deSEC API.

    Args:
        token: The authentication token value.

    """

    def __init__(self, token: str):
        self.token = token

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        """Attaches token-based Authorization header to a given Request object."""
        r.headers["Authorization"] = f"Token {self.token}"
        return r


class APIClient:
    """deSEC.io API client.

    Args:
        token: API authorization token
        request_timeout: HTTP request timeout in seconds. Note that the timeout is applied
            to individual HTTP requests and the methods of this class may make multiple
            requests. Set to `None` to disable.
        retry_limit: Number of retries when hitting the API's rate limit.
            Set to 0 to disable.
        logger: Logger instance to send HTTP debug information to. Defaults to the named
            logger `desec.client`.

    """

    def __init__(
        self,
        token: str,
        request_timeout: int | None = 15,
        retry_limit: int = 3,
        logger: logging.Logger = logging.getLogger("desec.client"),  # noqa: B008
    ):
        self._token_auth = TokenAuth(token)
        self._request_timeout = request_timeout
        self._retry_limit = retry_limit
        self.logger = logger
        "Logger instance to send HTTP debug information to."

    @staticmethod
    def _get_response_content(response: requests.Response) -> desec.types.JsonGenericType:
        """Safely get content from a response.

        Args:
            response: requests Response object

        Returns:
            If the response body contains JSON data, it is parsed into the respective
            Python data structures. Otherwise the response body as a string.
        """
        content_type = response.headers.get("Content-Type")
        if content_type == "text/dns":
            return response.text
        elif content_type == "application/json":
            try:
                return response.json()
            except ValueError:  # pragma: no cover
                return response.text
        else:
            return response.text

    @t.overload
    def query(
        self,
        method: t.Literal["DELETE", "GET"],
        url: str,
        data: t.Mapping[str, str | int | float | bool | None] | None = None,
    ) -> desec.types.JsonGenericType | str: ...

    @t.overload
    def query(
        self,
        method: t.Literal["PATCH", "POST", "PUT"],
        url: str,
        data: desec.types.JsonGenericType = None,
    ) -> desec.types.JsonGenericType | str: ...

    def query(
        self,
        method: t.Literal["DELETE", "GET", "PATCH", "POST", "PUT"],
        url: str,
        data: desec.types.JsonGenericType = None,
    ) -> desec.types.JsonGenericType | str:
        """Query the API.

        This method handles low-level queries to the deSEC API and should not be used
        directly. Prefer the more high-level methods that implement specific API functions
        instead.

        If the initial request hits the API's rate limit, it is retired up to
        `self._retry_limit` times, after waiting for the interval returned by the API.
        Unless another process is using the API in parallel, no more than one retry
        should be needed.

        If the API refuses to answer the query because it would return more data than the
        API's limit for a single response, the query is retried in pagination mode. This
        means that the API is queries repeatedly until all results are retrieved. The
        responses are merged and returned in a single list.

        Args:
            method: HTTP method to use.
            url: Target URL to query.
            data: Data to send in either the body or as URL parameters (for HTTP methods
                that do not support body parameters). URL parameters must be supplied as a
                simple key-value dictionary while body parameters may be more complex JSON
                structures.

        Returns:
            The response body.
            If the response body contains JSON data, it is parsed into the respective Python
            data structures.
            If the response body is empty, `None` is returned.

        Raises:
            desec.exceptions.ParameterError: The API returned status code 400 (Bad Request).
                Request parameters were incorrect or invalid.
            desec.exceptions.AuthenticationError: The API returned status code
                401 (Unauthorized).
                The supplied authentication token is not valid for this query (e.g. the
                domain is not managed by this account).
            desec.exceptions.TokenPermissionError: The API returned status code
                403 (Forbidden).
                The requested operation is not allowed for the given token (or account).
            desec.exceptions.NotFoundError: The API returned status code (Not Found).
                The object to operate on was not found (e.g. the domain or RRset).
            desec.exceptions.ConflictError: The API returned status code 409 (Conflict).
                The requested operation conflicts with existing data or a deSEC policy.
            desec.exceptions.RateLimitError: The API returned status code
                429 (Too Many Requests).
                The request hit the API's rate limit. Retries up to the configured limit
                were made, but also hit the rate limit.
            desec.exceptions.APIError: The API returned an unexpected error.
            requests.Timeout: The API failed to reply to an HTTP request within the time
                limit.

        """
        if method == "GET" or method == "DELETE":
            params = t.cast("t.Mapping[str, str | int | float | bool | None] | None", data)
            body = None
        else:
            params = None
            body = data

        merged_result = []
        next_url: str | None = url
        r = requests.Response()  # Without this line, mypy considers r as possibly undefined.
        while next_url is not None:
            retry_after = 0
            # Loop until we do not hit the rate limit (or we reach retry_limit + 1
            # iterations). Ideally, that should be only one or two iterations.
            for _ in range(max(1, self._retry_limit + 1)):
                # If we did hit the rate limit on the previous iteration, wait until it
                # expires.
                time.sleep(retry_after)
                # Send the request.
                self.logger.debug(
                    f"Request: {method} {url}",
                    extra=dict(method=method, url=url, params=params, body=body),
                )
                r = requests.request(
                    method,
                    next_url,
                    auth=self._token_auth,
                    params=params,
                    json=body,
                    timeout=self._request_timeout,
                )
                self.logger.debug(
                    f"Response: {r.status_code} for {method} {url}",
                    extra=dict(
                        response_code=r.status_code,
                        response_body=self._get_response_content(r),
                    ),
                )
                if r.status_code != 429:
                    # Not rate limited. Response is handled below.
                    break
                # Handle rate limiting. See https://desec.readthedocs.io/en/latest/rate-limits.html
                try:
                    retry_after = int(r.headers["Retry-After"])
                except (KeyError, ValueError) as e:  # pragma: no cover
                    # Retry-After header is missing or not an integer. This should never
                    # happen.
                    raise desec.exceptions.RateLimitError(response=r) from e
            else:
                # Reached retry_limit (or it is 0) without any other response than 429.
                raise desec.exceptions.RateLimitError(response=r)

            # Handle pagination. The API returns a "Link" header if the query requires
            # pagination. If the status code is 400, that means we did not request
            # pagination, but should have done so.
            # In this case, we redo the request using the "fist" URL from the "Link" header.
            # Otherwise, we use the "next" URL to get the next set of results.
            # Reference: https://desec.readthedocs.io/en/latest/dns/rrsets.html#pagination
            if "Link" in r.headers:
                if r.status_code == 400:
                    # Pagination is required. The "first" URL points to the starting point.
                    links = self.parse_links(r.headers["Link"])
                    next_url = links["first"]
                else:
                    # We got partial results from pagination. Merge them with the results we
                    # already have and go on with the "next" URL (if any).
                    merged_result.extend(r.json())
                    links = self.parse_links(r.headers["Link"])
                    next_url = links.get("next")
            else:
                # No pagination -> no further requests.
                break

        if r.status_code == 400:
            raise desec.exceptions.ParameterError(response=r)
        elif r.status_code == 401:
            raise desec.exceptions.AuthenticationError(response=r)
        elif r.status_code == 403:
            raise desec.exceptions.TokenPermissionError(response=r)
        elif r.status_code == 404:
            raise desec.exceptions.NotFoundError(response=r)
        elif r.status_code == 409:
            raise desec.exceptions.ConflictError(response=r)
        elif r.status_code >= 400:  # pragma: no cover
            raise desec.exceptions.APIError(response=r)

        # Get Header: Content-Type
        try:
            content_type = r.headers["Content-Type"]
        except KeyError:
            content_type = None

        # Process response data according to content-type.
        response_data: desec.types.JsonGenericType
        if content_type == "text/dns":
            response_data = r.text
        elif content_type == "application/json":
            if merged_result:
                # Merged results from paginated queries don't need further processing.
                response_data = merged_result
            else:
                try:
                    response_data = r.json()
                except ValueError:  # pragma: no cover
                    response_data = None
        else:
            response_data = None
        return response_data

    def parse_links(self, links: str) -> dict[str, str]:
        """Parse `Link:` response header used for pagination.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#pagination

        Args:
            links: `Link:` header returned by the API.

        Returns:
            A dictionary containing the URLs from the header, indexed by their respective
            `rel` attribute. In other words, the "next" attribute references the URL that
            returns the next portion of the requested data.

        Raises:
            desec.exceptions.APIExpectationError: Parsing the given `Link` response header
                failed.

        """
        mapping = {}
        for link in links.split(", "):
            _url, label = link.split("; ")
            m = re.search('rel="(.*)"', label)
            if m is None:  # pragma: no cover
                raise desec.exceptions.APIExpectationError("Unexpected format in Link header")
            label = m.group(1)
            _url = _url[1:-1]
            mapping[label] = _url
        return mapping

    def list_tokens(self) -> list[desec.types.JsonTokenType]:
        """Return information about all current tokens.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#retrieving-all-current-tokens

        Returns:
            A list of tokens that exist for the current account. Each token is returned as a
            dictionary containing all available token metadata. Note that the actual token
            values are not included, as the API does not return them.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/"
        data = self.query("GET", url)
        return t.cast("list[desec.types.JsonTokenType]", data)

    def create_token(
        self,
        name: str = "",
        manage_tokens: bool | None = None,
        create_domain: bool | None = None,
        delete_domain: bool | None = None,
        allowed_subnets: list[str] | None = None,
        auto_policy: bool | None = None,
    ) -> desec.types.JsonTokenSecretType:
        """Create a new authentication token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#create-additional-tokens

        Args:
            name: Set the "name" attribute of the new token to this value.
            manage_tokens: Set the "perm_manage_tokens" attribute of the new token to this
                value.
            create_domain: Set the "perm_create_domain" attribute of the new token to this
                value.
            delete_domain: Set the "perm_delete_domain" attribute of the new token to this
                value.
            allowed_subnets: Set the "allowed_subnets" attribute of the new token to this
                value.
            auto_policy: Set the "auto_policy" attribute of the new token to this value.

        Returns:
            A dictionary containing all metadata of the newly created token as well as the
            token value itself.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/"
        request_data: desec.types.JsonGenericType
        request_data = {"name": name}
        if manage_tokens is not None:
            request_data["perm_manage_tokens"] = manage_tokens
        if create_domain is not None:
            request_data["perm_create_domain"] = create_domain
        if delete_domain is not None:
            request_data["perm_delete_domain"] = delete_domain
        if allowed_subnets is not None:
            request_data["allowed_subnets"] = allowed_subnets
        if auto_policy is not None:
            request_data["auto_policy"] = auto_policy
        data = self.query("POST", url, request_data)
        return t.cast("desec.types.JsonTokenSecretType", data)

    def modify_token(
        self,
        token_id: str,
        name: str | None = None,
        manage_tokens: bool | None = None,
        create_domain: bool | None = None,
        delete_domain: bool | None = None,
        allowed_subnets: list[str] | None = None,
        auto_policy: bool | None = None,
    ) -> desec.types.JsonTokenType:
        """Modify an existing authentication token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#modifying-a-token

        Args:
            token_id: The unique id of the token to modify.
            name: Set the "name" attribute of the target token to this value.
            manage_tokens: Set the "perm_manage_tokens" attribute of the target token to
                this value.
            create_domain: Set the "perm_create_domain" attribute of the new token to this
                value.
            delete_domain: Set the "perm_delete_domain" attribute of the new token to this
                value.
            allowed_subnets: Set the "allowed_subnets" attribute of the target token to this
                value.
            auto_policy: Set the "auto_policy" attribute of the target token to this value.

        Returns:
            A dictionary containing all metadata of the changed token, not including the
            token value itself.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/"
        request_data: desec.types.JsonGenericType
        request_data = {}
        if name is not None:
            request_data["name"] = name
        if manage_tokens is not None:
            request_data["perm_manage_tokens"] = manage_tokens
        if create_domain is not None:
            request_data["perm_create_domain"] = create_domain
        if delete_domain is not None:
            request_data["perm_delete_domain"] = delete_domain
        if allowed_subnets is not None:
            request_data["allowed_subnets"] = allowed_subnets
        if auto_policy is not None:
            request_data["auto_policy"] = auto_policy
        data = self.query("PATCH", url, request_data)
        return t.cast("desec.types.JsonTokenType", data)

    def delete_token(self, token_id: str) -> None:
        """Delete an authentication token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#delete-tokens

        Args:
            token_id: The unique id of the token to delete.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/"
        _ = self.query("DELETE", url)

    def list_token_policies(self, token_id: str) -> list[desec.types.JsonTokenPolicyType]:
        """Return a list of all policies for the given token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies

        Args:
            token_id: The unique id of the token for which to get policies.

        Returns:
            A list of token policies for the given token. Each policy is returned as a
            dictionary containing all available policy data.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/"
        data = self.query("GET", url)
        return t.cast("list[desec.types.JsonTokenPolicyType]", data)

    def add_token_policy(
        self,
        token_id: str,
        domain: str | None = None,
        subname: str | None = None,
        rtype: str | None = None,
        perm_write: bool = False,
    ) -> desec.types.JsonTokenPolicyType:
        """Add a policy to the given token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies

        Args:
            token_id: The unique id of the token for which to add a policy.
            domain: The domain to which the policy applies. `None` indicates the default
                policy.
            subname: DNS entry name. `None` indicates the default policy.
            rtype: DNS record type. `None` indicates the default policy.
            perm_write: Boolean indicating whether to allow or deny writes.

        Returns:
            A dictionary containing all data of the newly created token policy.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.ConflictError: There is a conflicting policy for this token,
                domain, subname and type.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/"
        request_data: desec.types.JsonGenericType
        request_data = {
            "domain": domain,
            "subname": subname,
            "type": rtype,
            "perm_write": perm_write,
        }
        data = self.query("POST", url, request_data)
        return t.cast("desec.types.JsonTokenPolicyType", data)

    def modify_token_policy(
        self,
        token_id: str,
        policy_id: str,
        domain: str | None | t.Literal[False] = False,
        subname: str | None | t.Literal[False] = False,
        rtype: str | None | t.Literal[False] = False,
        perm_write: bool | None = None,
    ) -> desec.types.JsonTokenPolicyType:
        """Modify an existing policy for the given token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies

        Args:
            token_id: The unique id of the token for which to modify a policy.
            policy_id: The unique id of the policy to modify.
            domain: Set the domain to which the policy applies. `None` indicates the
                default policy. `False` leaves the value unchanged.
            subname: Set the DNS entry name. `None` indicates the default policy. `False`
                leaves the value unchanged.
            rtype: Set the DNS record type. `None` indicates the default policy. `False`
                leaves the value unchanged.
            perm_write: Boolean indicating whether to allow or deny writes. `None` leaves
                the value unchanged.

        Returns:
            A dictionary containing all data of the modified token policy.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.ConflictError: There is a conflicting policy for this token,
                domain, subname and type.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/{policy_id}/"
        request_data: desec.types.JsonGenericType
        request_data = {}
        if domain is not False:
            request_data["domain"] = domain
        if subname is not False:
            request_data["subname"] = subname
        if rtype is not False:
            request_data["type"] = rtype
        if perm_write is not None:
            request_data["perm_write"] = perm_write
        data = self.query("PATCH", url, request_data)
        return t.cast("desec.types.JsonTokenPolicyType", data)

    def delete_token_policy(self, token_id: str, policy_id: str) -> None:
        """Delete an existing policy for the given token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies

        Args:
            token_id: The unique id of the token for which to delete a policy.
            policy_id: The unique id of the policy to delete.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have the "perm_manage_tokens" attribute.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/{policy_id}/"
        _ = self.query("DELETE", url)

    def list_domains(self) -> list[desec.types.JsonDomainType]:
        """Return a list of all registered domains.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#listing-domains

        Returns:
            A list of all registered domains for the current account, including basic
            metadata.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/"
        data = self.query("GET", url)
        return t.cast("list[desec.types.JsonDomainType]", data)

    def domain_info(self, domain: str) -> desec.types.JsonDomainWithKeysType:
        """Return basic information about a domain.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#retrieving-a-specific-domain

        Args:
            domain: The name of the domain to retrieve.

        Returns:
            A dictionary containing all metadata for the given domain including DNSSEC key
            information.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.NotFoundError: The given domain was not found in the current
                account.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/"
        data = self.query("GET", url)
        return t.cast("desec.types.JsonDomainWithKeysType", data)

    def new_domain(self, domain: str) -> desec.types.JsonDomainWithKeysType:
        """Create a new domain.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#creating-a-domain

        Args:
            domain: The name of the domain to create.

        Returns:
            A dictionary containing all metadata for the newly created domain including
            DNSSEC key information.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.ParameterError: The given domain name is incorrect, conflicts
                with an existing domain or is disallowed by policy.
            desec.exceptions.TokenPermissionError: The token used for authentication can
                not create domains or the maximum number of domains for the current account
                has been reached.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/"
        data = self.query("POST", url, data={"name": domain})
        return t.cast("desec.types.JsonDomainWithKeysType", data)

    def delete_domain(self, domain: str) -> None:
        """Delete a domain.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#deleting-a-domain

        Args:
            domain: The name of the domain to delete.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have write permissions to the domain.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/"
        _ = self.query("DELETE", url)

    def export_zonefile_domain(self, domain: str) -> str:
        """Export a domain as a zonefile.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#exporting-a-domain-as-zonefile

        Args:
            domain: The name of the domain to export.

        Returns:
            All of the domain's non-DNSSEC records in plain-text zonefile format.

        Raises:
            desec.exceptions.NotFoundError: The given domain was not found in the current
                account.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/zonefile/"
        data = self.query("GET", url)
        return t.cast("str", data)

    def get_records(
        self,
        domain: str,
        rtype: desec.types.DnsRecordTypeType | None = None,
        subname: str | None = None,
    ) -> list[desec.types.JsonRRsetType]:
        """Return (a subset of) all RRsets of a domain.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#retrieving-all-rrsets-in-a-zone

        Args:
            domain: The name of the domain to query.
            rtype: Return only records of this DNS record type. `None` returns records of
                any type.
            subname: Return only records at this DNS entry name. `None` returns records for
                all names.

        Returns:
            A list of DNS records matching the given filters. Each record is returned as a
            dictionary containing all data and metadata of this RRset.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.NotFoundError: The given domain was not found in the current
                account.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url: str | None
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/"
        data = self.query("GET", url, {"subname": subname, "type": rtype})
        return t.cast("list[desec.types.JsonRRsetType]", data)

    def add_record(
        self,
        domain: str,
        rtype: desec.types.DnsRecordTypeType,
        subname: str,
        rrset: t.Sequence[str],
        ttl: int,
    ) -> desec.types.JsonRRsetType:
        """Add a new RRset.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#creating-an-rrset

        There must not be a RRset for this domain-type-subname combination. To modify an
        existing RRset use `change_record` or `update_record`.

        Args:
            domain: The name of the domain to add the RRset to.
            rtype: DNS record type of the new RRset.
            subname: DNS entry name of the new RRset.
            rrset: List of DNS record contents.
            ttl: TTL for new the RRset.

        Returns:
            A dictionary containing all data and metadata of the new RRset.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.NotFoundError: The given domain was not found in the current
                account.
            desec.exceptions.ParameterError: The RRset is invalid or conflicts with an
                existing RRset.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have write permissions to this record.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/"
        data = self.query(
            "POST", url, {"subname": subname, "type": rtype, "records": rrset, "ttl": ttl}
        )
        return t.cast("desec.types.JsonRRsetType", data)

    def update_bulk_record(
        self,
        domain: str,
        rrset_list: t.Sequence[desec.types.JsonRRsetWritableType],
        exclusive: bool = False,
    ) -> list[desec.types.JsonRRsetType]:
        """Update RRsets in bulk.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#bulk-operations

        Args:
            domain: The name of the domain for which to modify records.
            rrset_list: List of RRsets to update.
            exclusive: If `True`, all DNS records not in `rrset_list` are removed.

        Returns:
            A list of dictionaries containing all data and metadata of the updated RRsets.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.NotFoundError: The given domain was not found in the current
                account.
            desec.exceptions.ParameterError: The bulk operation failed.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/"

        if exclusive:
            # Delete all records not in rrset_list by adding RRsets with an empty 'records'
            # field for them.
            existing_records = [(r["subname"], r["type"]) for r in rrset_list]
            rrset_list = list(rrset_list)
            for r in self.get_records(domain):
                if (r["subname"], r["type"]) not in existing_records:
                    rrset_list.append({"subname": r["subname"], "type": r["type"], "records": []})

        data = self.query("PATCH", url, t.cast("desec.types.JsonGenericType", rrset_list))
        return t.cast("list[desec.types.JsonRRsetType]", data)

    def change_record(
        self,
        domain: str,
        rtype: desec.types.DnsRecordTypeType,
        subname: str,
        rrset: t.Sequence[str] | None = None,
        ttl: int | None = None,
    ) -> desec.types.JsonRRsetType:
        """Change an existing RRset.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#modifying-an-rrset

        Args:
            domain: The name of the domain for which to modify a record.
            rtype: DNS record type of the record to modify.
            subname: DNS entry name of the record to modify.
            rrset: Set the DNS record contents, removing any existing data. `None` leaves
                the record contents unchanged.
            ttl: Set this TTL for the given RRset. `None` leaves the TTL unchanged.

        Returns:
            A dictionary containing all data and metadata of the modified RRset.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.NotFoundError: The RRset to modify was not found in the current
                account.
            desec.exceptions.ParameterError: The RRset could not be changed to the given
                parameters.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have write permissions to this record.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/{subname}.../{rtype}/"
        request_data: desec.types.JsonGenericType
        request_data = {}
        if rrset:
            request_data["records"] = rrset
        if ttl:
            request_data["ttl"] = ttl
        data = self.query("PATCH", url, data=request_data)
        return t.cast("desec.types.JsonRRsetType", data)

    def delete_record(
        self,
        domain: str,
        rtype: desec.types.DnsRecordTypeType,
        subname: str,
        rrset: t.Sequence[str] | None = None,
    ) -> None:
        """Delete an existing RRset or delete records from an RRset.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#deleting-an-rrset

        Args:
            domain: The name of the domain for which to delete a record.
            rtype: DNS record type of the record to delete.
            subname: DNS entry name of the record to delete.
            rrset: A list of record contents to delete. `None` deletes the whole RRset.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.NotFoundError: The given domain was not found in the current
                account.
            TokenPermissionError: The token used for authentication does not have write
                permissions to this record.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        records_to_keep = None
        if rrset is not None:
            try:
                # Get the existing RRset (if any).
                data = self.get_records(domain, rtype, subname)[0]
            except IndexError:
                # This happens when get_records returns an empty list, i.e.
                # there is no RRset with the given parameters. So, there is
                # nothing to delete.
                return
            # Remove records that are in `rrset` from `data`.
            records_to_keep = [r for r in data["records"] if r not in rrset]
        if records_to_keep:
            # Some records should be kept, use change_record for that
            self.change_record(domain, rtype, subname, records_to_keep)
        else:
            # Nothing should be kept, delete the whole RRset
            url = f"{API_BASE_URL}/domains/{domain}/rrsets/{subname}.../{rtype}/"
            _ = self.query("DELETE", url)

    def update_record(
        self,
        domain: str,
        rtype: desec.types.DnsRecordTypeType,
        subname: str,
        rrset: list[str],
        ttl: int | None = None,
    ) -> desec.types.JsonRRsetType:
        """Change an existing RRset or create a new one.

        Records are added to the existing records (if any). `ttl` is used only when
        creating a new RRset. For existing RRsets, the existing TTL is kept.

        Args:
            domain: The name of the domain for which to modify or add a record.
            rtype: DNS record type of the record to modify or add.
            subname: DNS entry name of the record to modify or add.
            rrset: The DNS record contents to add.
            ttl: When creating a new RRset, set its TTL to this value. `None` is only valid
                if the target RRset already exists.

        Returns:
            A dictionary containing all data and metadata of the modified or created RRset.

        Raises:
            desec.exceptions.AuthenticationError: The token used for authentication is
                invalid.
            desec.exceptions.ParameterCheckError: The target RRset does not exist and `ttl`
                is `None`.
            desec.exceptions.ParameterError: The RRset could not be changed to the given
                parameters.
            desec.exceptions.TokenPermissionError: The token used for authentication does
                not have write permissions to this record.
            desec.exceptions.APIError: The API returned an unexpected error.

        """
        data = self.get_records(domain, rtype, subname)
        if not data:
            # There is no entry, simply create a new one
            if ttl is None:
                raise desec.exceptions.ParameterCheckError(
                    f"Missing TTL for new {rtype} record {subname}.{domain}."
                )
            return self.add_record(domain, rtype, subname, rrset, ttl)
        else:
            # Update the existing records with the given ones
            rrset.extend(data[0]["records"])
            return self.change_record(domain, rtype, subname, rrset)
