#!/usr/bin/env python3
"""Simple API client for desec.io.

It can be used as a standalone CLI tool or as a python module.
For more information on the CLI, run it with the --help parameter.
For more information on the module's classes and functions, refer to the respective
docstrings.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import typing as t
from datetime import datetime, timezone
from enum import IntEnum
from hashlib import sha256, sha512
from pprint import pprint

import requests

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    cryptography_available = True
except ModuleNotFoundError:
    cryptography_available = False

try:
    import dns.name
    from dns import rdatatype, zone

    dnspython_available = True
except ModuleNotFoundError:
    dnspython_available = False

if t.TYPE_CHECKING:
    import pathlib

__version__ = "0.0.0"

DnsRecordTypeType = t.Literal[
    "A",
    "AAAA",
    "AFSDB",
    "APL",
    "CAA",
    "CDNSKEY",
    "CDS",
    "CERT",
    "CNAME",
    "DHCID",
    "DNAME",
    "DNSKEY",
    "DLV",
    "DS",
    "EUI48",
    "EUI64",
    "HINFO",
    "HTTPS",
    "KX",
    "L32",
    "L64",
    "LOC",
    "LP",
    "MX",
    "NAPTR",
    "NID",
    "NS",
    "OPENPGPKEY",
    "PTR",
    "RP",
    "SMIMEA",
    "SPF",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
    "URI",
]
JsonGenericType = t.Union[
    None,
    int,
    float,
    str,
    bool,
    t.Sequence["JsonGenericType"],
    t.Mapping[str, "JsonGenericType"],
]


class JsonTokenType(t.TypedDict):
    """API token information."""

    allowed_subnets: list[str]
    created: str
    id: str
    is_valid: bool
    last_used: str | None
    max_age: str | None
    max_unused_period: str | None
    name: str
    perm_manage_tokens: bool


class JsonTokenSecretType(JsonTokenType):
    """API token information including the secret token value."""

    token: str


class JsonTokenPolicyType(t.TypedDict):
    """API token policy information."""

    id: str
    domain: str | None
    subname: str | None
    type: str | None
    perm_write: bool


class JsonDNSSECKeyInfoType(t.TypedDict):
    """DNSSEC public key information."""

    dnskey: str
    ds: list[str]
    flags: int
    keytype: str
    managed: bool


class JsonDomainType(t.TypedDict):
    """Domain information."""

    created: str
    minimum_ttl: int
    name: str
    published: str
    touched: str


class JsonDomainWithKeysType(JsonDomainType):
    """Domain information including DNSSEC public key information."""

    keys: list[JsonDNSSECKeyInfoType]


class JsonRRsetWritableType(t.TypedDict):
    """Writable fields of RRset information."""

    records: list[str]
    subname: str
    ttl: t.NotRequired[int]
    type: DnsRecordTypeType


class JsonRRsetType(JsonRRsetWritableType):
    """RRset information."""

    created: str
    domain: str
    name: str
    touched: str


class JsonRRsetFromZonefileType(JsonRRsetWritableType):
    """RRset information parsed from a zone file."""

    name: str
    error_msg: t.NotRequired[str]
    error_recovered: t.NotRequired[bool]


API_BASE_URL = "https://desec.io/api/v1"
RECORD_TYPES = t.get_args(DnsRecordTypeType)


class ExitCode(IntEnum):
    """Error codes use by the CLI tool and API related exceptions."""

    OK = 0
    GENERIC_ERROR = 1
    INVALID_PARAMETERS = 3
    API = 4
    AUTH = 5
    NOT_FOUND = 6
    TLSA_CHECK = 7
    RATE_LIMIT = 8
    PERMISSION = 9


class DesecClientError(Exception):
    """Exception for all errors within the client."""

    error_code = ExitCode.GENERIC_ERROR


class ParameterCheckError(DesecClientError):
    """Exception for parameter consistency check errors."""

    error_code = ExitCode.INVALID_PARAMETERS


class TLSACheckError(DesecClientError):
    """Exception for TLSA record setup consistency check errors."""

    error_code = ExitCode.TLSA_CHECK


class APIExpectationError(DesecClientError):
    """Exception for errors that are caused by unmet expectations in API responses."""

    error_code = ExitCode.GENERIC_ERROR


class APIError(DesecClientError):
    """Exception for errors returned by the API.

    If initialized with a HTTP response, an attempt is made to parse error information from
    the response and include it in the string representation of this exception, replacing
    the `{detail}` placeholder in the message template.

    Args:
        response: HTTP response from the deSEC API that caused this exception.

    """

    error_code = ExitCode.API
    message_template = "Unexpected error code {code}: {detail}"

    def __init__(self, response: requests.Response):
        self._response = response

    def __str__(self) -> str:
        """Return a string representation of this exception.

        The formatting is based on the message template and takes the HTTP response into
        account.
        The message template may contain the following placeholders:
        * `code`: Replaced by the HTTP status code.
        * `detail`: Replaced by the error message from the HTTP response, if it can be
            parsed.

        Returns:
            A human-readable text representation of the error condition.

        """
        if self._response.headers["Content-Type"] == "application/json":
            json_data = self._response.json()
            if not isinstance(json_data, list):
                json_data = [json_data]
            detail = ""
            for entry in json_data:
                try:
                    detail += t.cast(dict[t.Literal["detail"], str], entry)["detail"] + "\n"
                except KeyError:
                    for attribute, messages in entry.items():
                        detail += attribute + ":\n  " + "  \n".join(messages) + "\n"
            detail = detail.rstrip()
        else:
            detail = self._response.text
        return self.message_template.format(code=self._response.status_code, detail=detail)


class AuthenticationError(APIError):
    """Exception for authentication failure."""

    error_code = ExitCode.AUTH
    message_template = "Authentication error: {detail}"


class NotFoundError(APIError):
    """Exception when data can not be found."""

    error_code = ExitCode.NOT_FOUND
    message_template = "{detail}"


class ParameterError(APIError):
    """Exception for invalid parameters, such as DNS records."""

    error_code = ExitCode.INVALID_PARAMETERS
    message_template = "Invalid parameter(s):\n{detail}"


class ConflictError(APIError):
    """Exception for conflicts returned by the API."""

    error_code = ExitCode.INVALID_PARAMETERS
    message_template = "Conflict:\n{detail}"


class RateLimitError(APIError):
    """Exception for API rate limits."""

    error_code = ExitCode.RATE_LIMIT
    message_template = "Rate limited: {detail}"


class TokenPermissionError(APIError):
    """Exception for API insufficient token permissions."""

    error_code = ExitCode.PERMISSION
    message_template = "Restricted token: {detail}"


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


class TLSAField:
    """Abstract class for handling TLSA fields.

    This class (or its subclasses) allow using numeric values and symbolic names
    interchangeably.

    Args:
        value: The field value this objects represents. May be numeric or symbolic.

    Raises:
        ValueError: The supplied value is not valid for this type of field.

    """

    valid_values: tuple[str, ...]

    def __init__(self, value: str | int):
        try:
            value = self.valid_values.index(str(value).upper())
        except ValueError:
            pass
        self._value = int(value)
        try:
            self.valid_values[self._value]
        except IndexError as e:  # pragma: no cover
            raise ValueError(f"Invalid type {value} for {self.__class__}") from e

    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self._value == other
        elif isinstance(other, str):
            return self.valid_values[self._value] == other.upper()
        elif isinstance(other, self.__class__):
            return self._value == other._value
        return False  # pragma: no cover

    def __repr__(self) -> str:
        return self.valid_values[self._value]

    def __int__(self) -> int:
        return self._value


class TLSAUsage(TLSAField):
    """TLSA certificate usage information."""

    valid_values = ("PKIX-TA", "PKIX-EE", "DANE-TA", "DANE-EE")


class TLSASelector(TLSAField):
    """TLSA selector."""

    valid_values = ("CERT", "SPKI")


class TLSAMatchType(TLSAField):
    """TLSA match type."""

    valid_values = ("FULL", "SHA2-256", "SHA2-512")


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
    def _get_response_content(response: requests.Response) -> JsonGenericType:
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
    ) -> JsonGenericType | str: ...

    @t.overload
    def query(
        self, method: t.Literal["PATCH", "POST", "PUT"], url: str, data: JsonGenericType = None
    ) -> JsonGenericType | str: ...

    def query(
        self,
        method: t.Literal["DELETE", "GET", "PATCH", "POST", "PUT"],
        url: str,
        data: JsonGenericType = None,
    ) -> JsonGenericType | str:
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
            ParameterError: The API returned status code 400 (Bad Request).
                Request parameters were incorrect or invalid.
            AuthenticationError: The API returned status code 401 (Unauthorized).
                The supplied authentication token is not valid for this query (e.g. the
                domain is not managed by this account).
            TokenPermissionError: The API returned status code 403 (Forbidden).
                The requested operation is not allowed for the given token (or account).
            NotFoundError: The API returned status code (Not Found).
                The object to operate on was not found (e.g. the domain or RRset).
            ConflictError: The API returned status code 409 (Conflict).
                The requested operation conflicts with existing data or a deSEC policy.
            RateLimitError: The API returned status code 429 (Too Many Requests).
                The request hit the API's rate limit. Retries up to the configured limit
                were made, but also hit the rate limit.
            APIError: The API returned an unexpected error.
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
                    raise RateLimitError(response=r) from e
            else:
                # Reached retry_limit (or it is 0) without any other response than 429.
                raise RateLimitError(response=r)

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
            raise ParameterError(response=r)
        elif r.status_code == 401:
            raise AuthenticationError(response=r)
        elif r.status_code == 403:
            raise TokenPermissionError(response=r)
        elif r.status_code == 404:
            raise NotFoundError(response=r)
        elif r.status_code == 409:
            raise ConflictError(response=r)
        elif r.status_code >= 400:  # pragma: no cover
            raise APIError(response=r)

        # Get Header: Content-Type
        try:
            content_type = r.headers["Content-Type"]
        except KeyError:
            content_type = None

        # Process response data according to content-type.
        response_data: JsonGenericType
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
            APIExpectationError: Parsing the given `Link` response header failed.

        """
        mapping = {}
        for link in links.split(", "):
            _url, label = link.split("; ")
            m = re.search('rel="(.*)"', label)
            if m is None:
                raise APIExpectationError("Unexpected format in Link header")
            label = m.group(1)
            _url = _url[1:-1]
            mapping[label] = _url
        return mapping

    def list_tokens(self) -> list[JsonTokenType]:
        """Return information about all current tokens.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#retrieving-all-current-tokens

        Returns:
            A list of tokens that exist for the current account. Each token is returned as a
            dictionary containing all available token metadata. Note that the actual token
            values are not included, as the API does not return them.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/"
        data = self.query("GET", url)
        return t.cast(list[JsonTokenType], data)

    def create_token(
        self, name: str = "", manage_tokens: bool | None = None
    ) -> JsonTokenSecretType:
        """Create a new authentication token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#create-additional-tokens

        Args:
            name: Set the "name" attribute of the new token to this value.
            manage_tokens: Set the "manage_tokens" attribute of the new token to this value.

        Returns:
            A dictionary containing all metadata of the newly created token as well as the
            token value itself.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/"
        request_data: JsonGenericType
        request_data = {"name": name}
        if manage_tokens is not None:
            request_data["perm_manage_tokens"] = manage_tokens
        data = self.query("POST", url, request_data)
        return t.cast(JsonTokenSecretType, data)

    def modify_token(
        self, token_id: str, name: str | None = None, manage_tokens: bool | None = None
    ) -> JsonTokenType:
        """Modify an existing authentication token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#modifying-a-token

        Args:
            token_id: The unique id of the token to modify.
            name: Set the "name" attribute of the target token to this value.
            manage_tokens: Set the "manage_tokens" attribute of the target token to this
                value.

        Returns:
            A dictionary containing all metadata of the changed token, not including the
            token value itself.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/"
        request_data: JsonGenericType
        request_data = {}
        if name is not None:
            request_data["name"] = name
        if manage_tokens is not None:
            request_data["perm_manage_tokens"] = manage_tokens
        data = self.query("PATCH", url, request_data)
        return t.cast(JsonTokenType, data)

    def delete_token(self, token_id: str) -> None:
        """Delete an authentication token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#delete-tokens

        Args:
            token_id: The unique id of the token to delete.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/"
        _ = self.query("DELETE", url)

    def list_token_policies(self, token_id: str) -> list[JsonTokenPolicyType]:
        """Return a list of all policies for the given token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies

        Args:
            token_id: The unique id of the token for which to get policies.

        Returns:
            A list of token policies for the given token. Each policy is returned as a
            dictionary containing all available policy data.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/"
        data = self.query("GET", url)
        return t.cast(list[JsonTokenPolicyType], data)

    def add_token_policy(
        self,
        token_id: str,
        domain: str | None = None,
        subname: str | None = None,
        rtype: str | None = None,
        perm_write: bool = False,
    ) -> JsonTokenPolicyType:
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
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            ConflictError: There is a conflicting policy for this token, domain, subname
                and type.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/"
        request_data: JsonGenericType
        request_data = {
            "domain": domain,
            "subname": subname,
            "type": rtype,
            "perm_write": perm_write,
        }
        data = self.query("POST", url, request_data)
        return t.cast(JsonTokenPolicyType, data)

    def modify_token_policy(
        self,
        token_id: str,
        policy_id: str,
        domain: str | None | t.Literal[False] = False,
        subname: str | None | t.Literal[False] = False,
        rtype: str | None | t.Literal[False] = False,
        perm_write: bool | None = None,
    ) -> JsonTokenPolicyType:
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
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            ConflictError: There is a conflicting policy for this token, domain, subname
                and type.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/{policy_id}/"
        request_data: JsonGenericType
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
        return t.cast(JsonTokenPolicyType, data)

    def delete_token_policy(self, token_id: str, policy_id: str) -> None:
        """Delete an existing policy for the given token.

        See https://desec.readthedocs.io/en/latest/auth/tokens.html#token-scoping-policies

        Args:
            token_id: The unique id of the token for which to delete a policy.
            policy_id: The unique id of the policy to delete.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have the
                "manage_tokens" attribute.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/auth/tokens/{token_id}/policies/rrsets/{policy_id}/"
        _ = self.query("DELETE", url)

    def list_domains(self) -> list[JsonDomainType]:
        """Return a list of all registered domains.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#listing-domains

        Returns:
            A list of all registered domains for the current account, including basic
            metadata.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/"
        data = self.query("GET", url)
        return t.cast(list[JsonDomainType], data)

    def domain_info(self, domain: str) -> JsonDomainWithKeysType:
        """Return basic information about a domain.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#retrieving-a-specific-domain

        Args:
            domain: The name of the domain to retrieve.

        Returns:
            A dictionary containing all metadata for the given domain including DNSSEC key
            information.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            NotFoundError: The given domain was not found in the current account.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/"
        data = self.query("GET", url)
        return t.cast(JsonDomainWithKeysType, data)

    def new_domain(self, domain: str) -> JsonDomainWithKeysType:
        """Create a new domain.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#creating-a-domain

        Args:
            domain: The name of the domain to create.

        Returns:
            A dictionary containing all metadata for the newly created domain including
            DNSSEC key information.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            ParameterError: The given domain name is incorrect, conflicts with an existing
                domain or is disallowed by policy.
            TokenPermissionError: The token used for authentication can not create domains
                or the maximum number of domains for the current account has been reached.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/"
        data = self.query("POST", url, data={"name": domain})
        return t.cast(JsonDomainWithKeysType, data)

    def delete_domain(self, domain: str) -> None:
        """Delete a domain.

        See https://desec.readthedocs.io/en/latest/dns/domains.html#deleting-a-domain

        Args:
            domain: The name of the domain to delete.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            TokenPermissionError: The token used for authentication does not have write
                permissions to the domain.
            APIError: The API returned an unexpected error.

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
            NotFoundError: The given domain was not found in the current account.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/zonefile/"
        data = self.query("GET", url)
        return t.cast(str, data)

    def get_records(
        self, domain: str, rtype: DnsRecordTypeType | None = None, subname: str | None = None
    ) -> list[JsonRRsetType]:
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
            AuthenticationError: The token used for authentication is invalid.
            NotFoundError: The given domain was not found in the current account.
            APIError: The API returned an unexpected error.

        """
        url: str | None
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/"
        data = self.query("GET", url, {"subname": subname, "type": rtype})
        return t.cast(list[JsonRRsetType], data)

    def add_record(
        self, domain: str, rtype: DnsRecordTypeType, subname: str, rrset: t.Sequence[str], ttl: int
    ) -> JsonRRsetType:
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
            AuthenticationError: The token used for authentication is invalid.
            NotFoundError: The given domain was not found in the current account.
            ParameterError: The RRset is invalid or conflicts with an existing RRset.
            TokenPermissionError: The token used for authentication does not have write
                permissions to this record.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/"
        data = self.query(
            "POST", url, {"subname": subname, "type": rtype, "records": rrset, "ttl": ttl}
        )
        return t.cast(JsonRRsetType, data)

    def update_bulk_record(
        self, domain: str, rrset_list: t.Sequence[JsonRRsetWritableType], exclusive: bool = False
    ) -> list[JsonRRsetType]:
        """Update RRsets in bulk.

        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#bulk-operations

        Args:
            domain: The name of the domain for which to modify records.
            rrset_list: List of RRsets to update.
            exclusive: If `True`, all DNS records not in `rrset_list` are removed.

        Returns:
            A list of dictionaries containing all data and metadata of the updated RRsets.

        Raises:
            AuthenticationError: The token used for authentication is invalid.
            NotFoundError: The given domain was not found in the current account.
            ParameterError: The bulk operation failed.
            APIError: The API returned an unexpected error.

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

        data = self.query("PATCH", url, t.cast(JsonGenericType, rrset_list))
        return t.cast(list[JsonRRsetType], data)

    def change_record(
        self,
        domain: str,
        rtype: DnsRecordTypeType,
        subname: str,
        rrset: t.Sequence[str] | None = None,
        ttl: int | None = None,
    ) -> JsonRRsetType:
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
            AuthenticationError: The token used for authentication is invalid.
            NotFoundError: The RRset to modify was not found in the current account.
            ParameterError: The RRset could not be changed to the given parameters.
            TokenPermissionError: The token used for authentication does not have write
                permissions to this record.
            APIError: The API returned an unexpected error.

        """
        url = f"{API_BASE_URL}/domains/{domain}/rrsets/{subname}.../{rtype}/"
        request_data: JsonGenericType
        request_data = {}
        if rrset:
            request_data["records"] = rrset
        if ttl:
            request_data["ttl"] = ttl
        data = self.query("PATCH", url, data=request_data)
        return t.cast(JsonRRsetType, data)

    def delete_record(
        self,
        domain: str,
        rtype: DnsRecordTypeType,
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
            AuthenticationError: The token used for authentication is invalid.
            NotFoundError: The given domain was not found in the current account.
            TokenPermissionError: The token used for authentication does not have write
                permissions to this record.
            APIError: The API returned an unexpected error.

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
        rtype: DnsRecordTypeType,
        subname: str,
        rrset: list[str],
        ttl: int | None = None,
    ) -> JsonRRsetType:
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
            AuthenticationError: The token used for authentication is invalid.
            ParameterCheckError: The target RRset does not exist and `ttl` is `None`.
            ParameterError: The RRset could not be changed to the given parameters.
            TokenPermissionError: The token used for authentication does not have write
                permissions to this record.
            APIError: The API returned an unexpected error.

        """
        data = self.get_records(domain, rtype, subname)
        if not data:
            # There is no entry, simply create a new one
            if ttl is None:
                raise ParameterCheckError(
                    f"Missing TTL for new {rtype} record {subname}.{domain}."
                )
            return self.add_record(domain, rtype, subname, rrset, ttl)
        else:
            # Update the existing records with the given ones
            rrset.extend(data[0]["records"])
            return self.change_record(domain, rtype, subname, rrset)


def _print_records(rrset: JsonRRsetType | JsonRRsetFromZonefileType, **kwargs: t.Any) -> None:
    """Print a RRset in zone file format.

    Args:
        rrset: The RRset to print.
        **kwargs: Additional keyword arguments to print().

    """
    for record in rrset["records"]:
        line = f"{rrset['name']} {rrset['ttl']} IN {rrset['type']} {record}"
        print(line, **kwargs)


def _print_rrsets(
    rrsets: t.Sequence[JsonRRsetType | JsonRRsetFromZonefileType], **kwargs: t.Any
) -> None:
    """Print multiple RRsets in zone file format.

    Args:
        rrsets: The RRsets to print.
        **kwargs: Additional keyword arguments to print().

    """
    for rrset in rrsets:
        _print_records(rrset, **kwargs)


def sanitize_records(rtype: DnsRecordTypeType, subname: str, rrset: list[str]) -> list[str]:
    """Check the given DNS records for common errors and return a copy with fixed data.

    See https://desec.readthedocs.io/en/latest/dns/rrsets.html#caveats

    This function corrects fixable errors and raises an exception if there remain errors
    that are not trivially fixable.

    Args:
        rtype: DNS record type to check.
        subname: DNS entry name to check.
        rrset: List of DNS record contents to check.

    Returns:
        The `rrset` parameter, possibly with applied fixes.

    Raises:
        ParameterCheckError: An unfixable error was found.

    """
    if rtype == "CNAME" and rrset and len(rrset) > 1:
        # Multiple CNAME records in the same rrset are not legal.
        raise ParameterCheckError("Multiple CNAME records are not allowed.")
    if rtype in ("CNAME", "MX", "NS") and rrset:
        # CNAME and MX records must end in a .
        rrset = [r + "." if r[-1] != "." else r for r in rrset]
    if rtype == "CNAME" and subname == "":
        # CNAME in the zone apex can break the zone
        raise ParameterCheckError("CNAME records in the zone apex are not allowed.")
    if rtype == "NS" and "*" in subname:
        # Wildcard NS records do not play well with DNSSEC
        raise ParameterCheckError("Wildcard NS records are not allowed.")
    if rtype == "TXT" and rrset:
        # TXT records must be in ""
        rrset = [f'"{r}"' if r[0] != '"' or r[-1] != '"' else r for r in rrset]
    return rrset


def parse_zone_file(
    path: str | pathlib.Path, domain: str, minimum_ttl: int = 3600
) -> list[JsonRRsetFromZonefileType]:
    """Parse a zone file into a list of RRsets that can be supplied to the API.

    The list of RRsets may contain invalid records. It should be passed to
    `clear_errors_from_record_list` before passing it to the API.

    Args:
        path: Path to the zone file to parse.
        domain: The domain name of all records in the zone file.
        minimum_ttl: The Minimum TTL value for records in the target domain.

    Returns:
        A list of dictionaries describing the DNS records in the zone file with additional
        error information for records with errors.

    """
    # Let dnspython parse the zone file.
    parsed_zone = zone.from_file(path, origin=domain, relativize=False, check_origin=False)

    # Convert the parsed data into a dictionary and do some error detection.
    record_list: list[JsonRRsetFromZonefileType]
    record_list = []
    for name, rrset in parsed_zone.iterate_rdatasets():
        # Store error information of the current rrset as a dict of a human-readable
        # error message and a boolean indicating whether the error was fixed.
        # Only one error is stored, even if the line has multiple errors.
        class ErrorInfoType(t.TypedDict):
            error_msg: str
            error_recovered: bool

        error: ErrorInfoType | None
        error = None

        # Convert subname to string for further processing.
        subname = name.relativize(dns.name.from_text(domain)).to_text()

        # @ may be used for the zone apex in zone files. But we (and the deSEC API) use
        # the empty string instead.
        if subname == "@":
            subname = ""

        if rrset.ttl < minimum_ttl:
            error = {
                "error_msg": f"TTL {rrset.ttl} smaller than minimum of {minimum_ttl} seconds.",
                "error_recovered": True,
            }
            rrset.ttl = minimum_ttl

        if rdatatype.to_text(rrset.rdtype) not in RECORD_TYPES:
            error = {
                "error_msg": f"Record type {rdatatype.to_text(rrset.rdtype)} is not supported.",
                "error_recovered": False,
            }

        records = [r.to_text() for r in rrset]
        try:
            records = sanitize_records(
                t.cast(DnsRecordTypeType, rdatatype.to_text(rrset.rdtype)), subname, records
            )
        except ParameterCheckError as e:
            error = {"error_msg": str(e), "error_recovered": False}

        entry: JsonRRsetFromZonefileType
        entry = {
            "name": f"{subname}.{domain}.",
            "subname": subname,
            "type": t.cast(DnsRecordTypeType, rdatatype.to_text(rrset.rdtype)),
            "records": records,
            "ttl": rrset.ttl,
        }
        if error is not None:
            entry.update(error)
        record_list.append(entry)

    return record_list


def clear_errors_from_record_list(
    record_list: t.Sequence[JsonRRsetFromZonefileType],
) -> list[JsonRRsetFromZonefileType]:
    """Remove error information added by `parse_zone_file` and all items with errors.

    Args:
        record_list: A list of dictionaries describing DNS records with additional error
            information for records with errors, as returned by `parse_zone_file`.

    Returns:
        A list of dictionaries describing DNS records without error information or
        records that were marked as erroneous.

    """
    # Remove all items with non-recoverable errors.
    record_list = [r for r in record_list if r.get("error_recovered", True)]
    # Remove error information from the remaining items.
    for r in record_list:
        r.pop("error_msg", None)
        r.pop("error_recovered", None)
    return record_list


def tlsa_record(
    file: str | pathlib.Path,
    usage: TLSAUsage = TLSAUsage("DANE-EE"),
    selector: TLSASelector = TLSASelector("Cert"),
    match_type: TLSAMatchType = TLSAMatchType("SHA2-256"),
    check: bool = True,
    subname: str | None = None,
    domain: str | None = None,
) -> str:
    """Return the TLSA record for the given certificate, usage, selector and match_type.

    Args:
        file: Path to the X.509 certificate to generate the record for. PEM and DER encoded
            files work.
        usage: Usage value for the TLSA record. See RFC 6698, Section 2.1.1
        selector: Selector value for the TLS record. See RFC 6698, Section 2.1.2
        match_type: Match type value for the TLS record. See RFC 6698, Section 2.1.3
        check: Whether to do consistency checks on the input data.
        subname: Subname the TLSA record will be valid for. Only used when `check` is True.
        domain: Domain the TLSA record will be valid for. Only used when `check` is True.

    Returns:
        A string containing the RRset data for a TLSA record for the given parameters.

    Raises:
        TLSACheckError: The certificate type and usage type do not match or the certificate
            is not valid for the given host name.

    """
    # Read the certifiate from `file`.
    with open(file, "rb") as f:
        cert_data = f.read()
    # Parse the certificate.
    if cert_data.startswith(b"-----BEGIN CERTIFICATE-----"):
        # PEM format
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    else:
        # DER format
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

    # Do some sanity checks.
    if check:
        # Check certificate expiration.
        if cert.not_valid_after_utc <= datetime.now(timezone.utc):
            raise TLSACheckError(f"Certificate expired on {cert.not_valid_after_utc}")
        # Check is usage matches the certificate's CA status.
        is_ca_cert = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        if is_ca_cert and usage not in ["PKIX-TA", "DANE-TA"]:
            raise TLSACheckError(
                "CA certificate given for end entity usage. Please select a "
                "different certificate or set usage to PKIX-TA or DANE-TA."
            )
        elif not is_ca_cert and usage not in ["PKIX-EE", "DANE-EE"]:
            raise TLSACheckError(
                "Non-CA certificate given for CA usage. Please select a "
                "different certificate or set usage to PKIX-EE or DANE-EE."
            )
        # Check if any SAN matches the subname + domain
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if domain is not None:
            if subname:
                target_name = f"{subname}.{domain}"
            else:
                target_name = domain
            for name in san.value.get_values_for_type(x509.DNSName):
                if name == target_name:
                    break
            else:
                sans = ", ".join(san.value.get_values_for_type(x509.DNSName))
                raise TLSACheckError(f"Certificate is valid for {sans}, but not {target_name}.")

    # Determine what to put in the TLSA record.
    if selector == "SPKI":
        # Only the DER encoded public key.
        data = cert.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
    else:
        # Full DER encoded certificate.
        data = cert.public_bytes(encoding=Encoding.DER)

    # Encode the data.
    if match_type == "Full":
        hex_data = data.hex()
    elif match_type == "SHA2-256":
        hex_data = sha256(data).hexdigest()
    elif match_type == "SHA2-512":
        hex_data = sha512(data).hexdigest()
    else:
        raise NotImplementedError(f"TLSA match type {match_type} is not implemented.")

    return f"{int(usage)} {int(selector)} {int(match_type)} {hex_data}"


class _CliClientFormatter(logging.Formatter):
    """Pretty prints requests and response logs for CLI usage."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record for cli usage.

        Args:
            record: Log record to format.

        Returns:
            Formatted log record as string.
        """
        message = record.getMessage()
        if params := getattr(record, "params", None):
            message += "\nParams:"
            for k, v in params.items():
                message += f"{k}: {v}"
        if body := getattr(record, "body", None):
            message += "\nBody:\n"
            message += json.dumps(body, indent=2)
        if response_body := getattr(record, "response_body", None):
            message += "\n"
            message += json.dumps(response_body, indent=2)
            message += "\n"
        return message


def _configure_cli_logging(level: int) -> None:
    """Set up logging configuration when using the module as a command-line interface.

    Args:
        level: Logging level to set for desec.client logger.
    """
    http_handler = logging.StreamHandler(stream=sys.stderr)
    http_formatter = _CliClientFormatter()
    http_handler.setFormatter(http_formatter)
    http_logger = logging.getLogger("desec.client")
    http_logger.addHandler(http_handler)
    http_logger.setLevel(level)


def _main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="A simple deSEC.io API client")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p_action = parser.add_subparsers(dest="action", metavar="action")
    p_action.required = True

    g = parser.add_mutually_exclusive_group()
    g.add_argument("--token", help="API authentication token")
    g.add_argument(
        "--token-file",
        default=os.path.join(os.environ.get("XDG_CONFIG_HOME", "~/.config"), "desec", "token"),
        help="file containing the API authentication token (default: $XDG_CONFIG_HOME/desec/token)",
    )

    parser.add_argument(
        "--non-blocking",
        dest="block",
        action="store_false",
        default=True,
        help="When the API's rate limit is reached, return an appropriate error.",
    )
    parser.add_argument(
        "--blocking",
        dest="block",
        action="store_true",
        default=True,
        help="When the API's rate limit is reached, wait and retry the request. "
        "This is the default behaviour.",
    )

    parser.add_argument(
        "--debug-http", action="store_true", help="Print details about http requests / responses."
    )
    p = p_action.add_parser("list-tokens", help="list all authentication tokens")

    p = p_action.add_parser("create-token", help="create and return a new authentication token")
    p.add_argument("--name", default="", help="token name")
    p.add_argument(
        "--manage-tokens",
        action="store_true",
        default=False,
        help="create a token that can manage tokens",
    )

    p = p_action.add_parser("modify-token", help="modify an existing authentication token")
    p.add_argument("id", help="token id")
    p.add_argument("--name", default=None, help="token name")
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--manage-tokens",
        dest="manage_tokens",
        action="store_true",
        default=None,
        help="allow this token to manage tokens",
    )
    g.add_argument(
        "--no-manage-tokens",
        dest="manage_tokens",
        action="store_false",
        default=None,
        help="do not allow this token to manage tokens",
    )

    p = p_action.add_parser("delete-token", help="delete an authentication token")
    p.add_argument("id", help="token id")

    p = p_action.add_parser(
        "list-token-policies", help="list all policies of an authentication token"
    )
    p.add_argument("id", help="token id")

    p = p_action.add_parser("add-token-policy", help="add a policy for an authentication token")
    p.add_argument("id", help="token id")
    p.add_argument("--domain", default=None, help="domain to which the policy applies")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        default=None,
        help="record type to which the policy applies",
    )
    p.add_argument("-s", "--subname", default=None, help="subname to which the policy applies")
    p.add_argument("--write", action="store_true", default=False, help="allow write access")

    p = p_action.add_parser(
        "modify-token-policy", help="modify an existing policy for an authentication token"
    )
    p.add_argument("token_id", help="token id")
    p.add_argument("policy_id", help="policy id")
    p.add_argument("--domain", default=False, help="domain to which the policy applies")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        default=False,
        help="record type to which the policy applies",
    )
    p.add_argument("-s", "--subname", default=False, help="subname to which the policy applies")

    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--write", dest="write", action="store_true", default=None, help="allow write access"
    )
    g.add_argument(
        "--no-write",
        dest="write",
        action="store_false",
        default=None,
        help="do not allow write access",
    )

    p = p_action.add_parser(
        "delete-token-policy", help="delete an existing policy for an authentication token"
    )
    p.add_argument("token_id", help="token id")
    p.add_argument("policy_id", help="policy id")

    p = p_action.add_parser("list-domains", help="list all registered domains")

    p = p_action.add_parser("domain-info", help="get information about a domain")
    p.add_argument("domain", help="domain name")

    p = p_action.add_parser("new-domain", help="create a new domain")
    p.add_argument("domain", help="domain name")

    p = p_action.add_parser("delete-domain", help="delete a domain")
    p.add_argument("domain", help="domain name")

    p = p_action.add_parser("get-records", help="list all records of a domain")
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        help="list only records of the given type",
    )
    p.add_argument("-s", "--subname", help="list only records for the given subname")

    p = p_action.add_parser("add-record", help="add a record set to the domain")
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        required=True,
        help="record type to add",
    )
    p.add_argument(
        "-s", "--subname", default="", help="subname to add, omit to add a record to the zone apex"
    )
    p.add_argument(
        "-r",
        "--records",
        required=True,
        nargs="+",
        metavar="RECORD",
        help="the DNS record(s) to add",
    )
    p.add_argument(
        "--ttl", type=int, default=3600, help="set the record's TTL (default: %(default)i seconds)"
    )

    p = p_action.add_parser("change-record", help="change an existing record set")
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        required=True,
        help="record type to change",
    )
    p.add_argument(
        "-s",
        "--subname",
        default="",
        help="subname to change, omit to change a record in the zone apex",
    )
    p.add_argument("-r", "--records", nargs="+", metavar="RECORD", help="the new DNS record(s)")
    p.add_argument("--ttl", type=int, help="the new TTL")

    p = p_action.add_parser("delete-record", help="delete a record set")
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        required=True,
        help="record type to delete",
    )
    p.add_argument(
        "-s",
        "--subname",
        default="",
        help="subname to delete, omit to delete a record from the zone apex",
    )
    p.add_argument(
        "-r",
        "--records",
        nargs="+",
        metavar="RECORD",
        help="the DNS records to delete (default: all)",
    )

    p = p_action.add_parser(
        "update-record", help="add entries, possibly to an existing record set"
    )
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=RECORD_TYPES,
        metavar="TYPE",
        required=True,
        help="record type to add",
    )
    p.add_argument(
        "-s", "--subname", default="", help="subname to add, omit to add a record to the zone apex"
    )
    p.add_argument(
        "-r",
        "--records",
        nargs="+",
        required=True,
        metavar="RECORD",
        help="the DNS records to add",
    )
    p.add_argument(
        "--ttl",
        type=int,
        default=3600,
        help="set the record's TTL, if creating a new record set (default: %(default)i seconds)",
    )

    if cryptography_available:
        p = p_action.add_parser(
            "add-tlsa",
            help="add a TLSA record for a X.509 certificate (aka DANE), keeping any existing "
            "records",
        )
        p.add_argument("domain", help="domain name")
        p.add_argument(
            "-s",
            "--subname",
            default="",
            help="subname that the record is valid for, omit to set a record to the zone apex",
        )
        p.add_argument(
            "-p", "--ports", nargs="+", required=True, help="ports that use the certificate"
        )
        p.add_argument(
            "--protocol",
            choices=["tcp", "udp", "sctp"],
            default="tcp",
            help="protocol that the given ports use (default: %(default)s)",
        )
        p.add_argument(
            "-c",
            "--certificate",
            required=True,
            help="file name of the X.509 certificate for which to set TLSA records (DER or PEM "
            "format)",
        )
        p.add_argument(
            "--usage",
            type=TLSAUsage,
            default=TLSAUsage("DANE-EE"),
            choices=[
                TLSAUsage("PKIX-TA"),
                TLSAUsage("PKIX-EE"),
                TLSAUsage("DANE-TA"),
                TLSAUsage("DANE-EE"),
            ],
            help="TLSA certificate usage information. Accepts numeric values or RFC 7218 symbolic "
            "names (default: %(default)s)",
        )
        p.add_argument(
            "--selector",
            type=TLSASelector,
            default=TLSASelector("Cert"),
            choices=[TLSASelector("Cert"), TLSASelector("SPKI")],
            help="TLSA selector. Accepts numeric values or RFC 7218 symbolic names "
            "(default: %(default)s)",
        )
        p.add_argument(
            "--match-type",
            type=TLSAMatchType,
            default=TLSAMatchType("SHA2-256"),
            choices=[TLSAMatchType("Full"), TLSAMatchType("SHA2-256"), TLSAMatchType("SHA2-512")],
            help="TLSA matching type. Accepts numeric values or RFC 7218 symbolic names "
            "(default: %(default)s)",
        )
        p.add_argument(
            "--ttl",
            type=int,
            default=3600,
            help="set the record's TTL, if creating a new record set "
            "(default: %(default)i seconds)",
        )
        p.add_argument(
            "--no-check",
            action="store_false",
            dest="check",
            default=True,
            help="skip any sanity checks and set the TLSA record as specified",
        )

        p = p_action.add_parser(
            "set-tlsa",
            help="set the TLSA record for a X.509 certificate (aka DANE), removing any existing "
            "records for the same port, protocol and subname",
        )
        p.add_argument("domain", help="domain name")
        p.add_argument(
            "-s",
            "--subname",
            default="",
            help="subname that the record is valid for, omit to set a record to the zone apex",
        )
        p.add_argument(
            "-p", "--ports", nargs="+", required=True, help="ports that use the certificate"
        )
        p.add_argument(
            "--protocol",
            choices=["tcp", "udp", "sctp"],
            default="tcp",
            help="protocol that the given ports use (default: %(default)s)",
        )
        p.add_argument(
            "-c",
            "--certificate",
            required=True,
            help="file name of the X.509 certificate for which to set TLSA records (DER or PEM "
            "format)",
        )
        p.add_argument(
            "--usage",
            type=TLSAUsage,
            default=TLSAUsage("DANE-EE"),
            choices=[
                TLSAUsage("PKIX-TA"),
                TLSAUsage("PKIX-EE"),
                TLSAUsage("DANE-TA"),
                TLSAUsage("DANE-EE"),
            ],
            help="TLSA certificate usage information. Accepts numeric values or RFC 7218 symbolic "
            "names (default: %(default)s)",
        )
        p.add_argument(
            "--selector",
            type=TLSASelector,
            default=TLSASelector("Cert"),
            choices=[TLSASelector("Cert"), TLSASelector("SPKI")],
            help="TLSA selector. Accepts numeric values or RFC 7218 symbolic names "
            "(default: %(default)s)",
        )
        p.add_argument(
            "--match-type",
            type=TLSAMatchType,
            default=TLSAMatchType("SHA2-256"),
            choices=[TLSAMatchType("Full"), TLSAMatchType("SHA2-256"), TLSAMatchType("SHA2-512")],
            help="TLSA matching type. Accepts numeric values or RFC 7218 symbolic names "
            "(default: %(default)s)",
        )
        p.add_argument(
            "--ttl",
            type=int,
            default=3600,
            help="set the record's TTL, if creating a new record set "
            "(default: %(default)i seconds)",
        )
        p.add_argument(
            "--no-check",
            action="store_false",
            dest="check",
            default=True,
            help="skip any sanity checks and set the TLSA record as specified",
        )

    p = p_action.add_parser("export", help="export all records into a file")
    p.add_argument("domain", help="domain name")
    p.add_argument("-f", "--file", required=True, help="target file name")

    p = p_action.add_parser("export-zone", help="export all records into a zone file")
    p.add_argument("domain", help="domain name")
    p.add_argument("-f", "--file", required=True, help="target file name")

    p = p_action.add_parser("import", help="import records from a file")
    p.add_argument("domain", help="domain name")
    p.add_argument("-f", "--file", required=True, help="target file name")
    p.add_argument(
        "--clear", action="store_true", help="remove all existing records before import"
    )

    if dnspython_available:
        p = p_action.add_parser("import-zone", help="import records from a zone file")
        p.add_argument("domain", help="domain name")
        p.add_argument("-f", "--file", required=True, help="target file name")
        p.add_argument(
            "--clear", action="store_true", help="remove all existing records before import"
        )
        p.add_argument(
            "-d",
            "--dry-run",
            action="store_true",
            help="just parse zone data, but do not write it to the API",
        )

    arguments = parser.parse_args()
    del p_action, g, p, parser
    _configure_cli_logging(level=logging.DEBUG if arguments.debug_http else logging.INFO)

    if arguments.token:
        token = arguments.token
    else:
        with open(os.path.expanduser(arguments.token_file)) as f:
            token = f.readline().strip()
    if arguments.block:
        api_client = APIClient(token)
    else:
        api_client = APIClient(token, retry_limit=0)
    del token

    try:
        if arguments.action == "list-tokens":
            tokens_result = api_client.list_tokens()
            pprint(tokens_result)

        elif arguments.action == "create-token":
            new_token_result = api_client.create_token(arguments.name, arguments.manage_tokens)
            print(new_token_result["token"])

        elif arguments.action == "modify-token":
            token_result = api_client.modify_token(
                arguments.id, arguments.name, arguments.manage_tokens
            )
            pprint(token_result)

        elif arguments.action == "delete-token":
            api_client.delete_token(arguments.id)

        elif arguments.action == "list-token-policies":
            policies_result = api_client.list_token_policies(arguments.id)
            pprint(policies_result)

        elif arguments.action == "add-token-policy":
            policy_result = api_client.add_token_policy(
                arguments.id, arguments.domain, arguments.subname, arguments.type, arguments.write
            )
            pprint(policy_result)

        elif arguments.action == "modify-token-policy":
            policy_result = api_client.modify_token_policy(
                arguments.token_id,
                arguments.policy_id,
                arguments.domain,
                arguments.subname,
                arguments.type,
                arguments.write,
            )
            pprint(policy_result)

        elif arguments.action == "delete-token-policy":
            api_client.delete_token_policy(arguments.token_id, arguments.policy_id)

        elif arguments.action == "list-domains":
            domains_result = api_client.list_domains()
            for d in domains_result:
                print(d["name"])

        elif arguments.action == "domain-info":
            domain_result = api_client.domain_info(arguments.domain)
            pprint(domain_result)

        elif arguments.action == "new-domain":
            domain_result = api_client.new_domain(arguments.domain)
            pprint(domain_result)

        elif arguments.action == "delete-domain":
            api_client.delete_domain(arguments.domain)

        elif arguments.action == "get-records":
            rrsets_result = api_client.get_records(
                arguments.domain, arguments.type, arguments.subname
            )
            for rrset in rrsets_result:
                _print_records(rrset)

        elif arguments.action == "add-record":
            arguments.records = sanitize_records(
                arguments.type, arguments.subname, arguments.records
            )
            rrset_result = api_client.add_record(
                arguments.domain,
                arguments.type,
                arguments.subname,
                arguments.records,
                arguments.ttl,
            )
            _print_records(rrset_result)

        elif arguments.action == "change-record":
            arguments.records = sanitize_records(
                arguments.type, arguments.subname, arguments.records
            )
            rrset_result = api_client.change_record(
                arguments.domain,
                arguments.type,
                arguments.subname,
                arguments.records,
                arguments.ttl,
            )
            _print_records(rrset_result)

        elif arguments.action == "update-record":
            arguments.records = sanitize_records(
                arguments.type, arguments.subname, arguments.records
            )
            rrset_result = api_client.update_record(
                arguments.domain,
                arguments.type,
                arguments.subname,
                arguments.records,
                arguments.ttl,
            )
            _print_records(rrset_result)

        elif arguments.action == "delete-record":
            if arguments.records:
                arguments.records = sanitize_records(
                    arguments.type, arguments.subname, arguments.records
                )
            api_client.delete_record(
                arguments.domain, arguments.type, arguments.subname, arguments.records
            )

        elif arguments.action == "add-tlsa" or arguments.action == "set-tlsa":
            record = tlsa_record(
                arguments.certificate,
                arguments.usage,
                arguments.selector,
                arguments.match_type,
                arguments.check,
                arguments.subname,
                arguments.domain,
            )

            records: list[JsonRRsetWritableType]
            records = []
            for port in arguments.ports:
                subname = f"_{port}._{arguments.protocol}.{arguments.subname}"
                if arguments.action == "add-tlsa":
                    try:
                        existing_rrset = api_client.get_records(arguments.domain, "TLSA", subname)[
                            0
                        ]["records"]
                    except IndexError:
                        # There is no existing TLSA RRset at this subname.
                        existing_rrset = []
                else:
                    existing_rrset = []
                records.append(
                    {
                        "type": "TLSA",
                        "subname": subname,
                        "records": [*existing_rrset, record],
                        "ttl": arguments.ttl,
                    }
                )

            rrsets_result = api_client.update_bulk_record(arguments.domain, records)
            _print_rrsets(rrsets_result)

        elif arguments.action == "export":
            rrsets_result = api_client.get_records(arguments.domain)
            # Write the data to the export file in json format
            with open(arguments.file, "w") as f:
                json.dump(rrsets_result, f)

        elif arguments.action == "export-zone":
            zone_result = api_client.export_zonefile_domain(arguments.domain)
            # Write the data to the export file in zonefile format
            with open(arguments.file, "w") as f:
                f.write(zone_result)

        elif arguments.action == "import":
            with open(arguments.file) as f:
                records = json.load(f)
            # Create the domain if it does not exist.
            try:
                api_client.domain_info(arguments.domain)
            except NotFoundError:
                api_client.new_domain(arguments.domain)

            rrsets_result = api_client.update_bulk_record(
                arguments.domain, records, arguments.clear
            )
            _print_rrsets(rrsets_result)

        elif arguments.action == "import-zone":
            record_list = parse_zone_file(
                arguments.file,
                arguments.domain,
                api_client.domain_info(arguments.domain)["minimum_ttl"],
            )
            for entry in record_list:
                if "error_msg" in entry:
                    error_action = "Corrected" if entry["error_recovered"] else "Skipped"
                    print(f"{entry['error_msg']} {error_action}.", file=sys.stderr)
            record_list = clear_errors_from_record_list(record_list)

            if arguments.dry_run:
                print(
                    "Dry run. Not writing changes to API. I would have written this:",
                    file=sys.stderr,
                )
                _print_rrsets(record_list)
            else:
                rrsets_result = api_client.update_bulk_record(
                    arguments.domain, record_list, arguments.clear
                )
                _print_rrsets(rrsets_result)

    except DesecClientError as e:
        print(str(e))
        sys.exit(e.error_code)


if __name__ == "__main__":
    _main()
