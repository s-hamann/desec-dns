"""Custom exception definitions."""

from __future__ import annotations

import typing as t
from enum import IntEnum

if t.TYPE_CHECKING:
    import requests


class ExitCode(IntEnum):
    """Error codes used by the CLI tool and API related exceptions."""

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
    """Numeric error code from the `ExitCode` enum. Exit code suggestion for CLI
    implementations."""


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
    """Template for the string representation of the exception. `{code}` gets replaced by
    the HTTP status code and `{detail}` by the message from the HTTP response body, if it
    can be parsed."""

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
                    detail += t.cast("dict[t.Literal['detail'], str]", entry)["detail"] + "\n"
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
