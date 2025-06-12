"""Data types and functions for DANE / TLSA record handling."""

from __future__ import annotations

import typing as t
from datetime import datetime, timezone
from hashlib import sha256, sha512

import desec.exceptions

CRYPTOGRAPHY_AVAILABLE = False
"""Whether the `cryptography` module can be imported. Functionality is limited if it is not
avaiable."""
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    CRYPTOGRAPHY_AVAILABLE = True
except ModuleNotFoundError:
    pass

if t.TYPE_CHECKING:
    import pathlib


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
    """Tuple of valid symbolic values for this kind of TLSA field. Numeric values are
    inferred from the order."""

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

    Note: This function requires the `cryptography` module.

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
        ModuleNotFoundError: The `cryptography` module could not be imported (on import of
            this module).
        desec.exceptions.TLSACheckError: The certificate type and usage type do not match
            or the certificate is not valid for the given host name.

    """
    if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
        raise ModuleNotFoundError("Module 'cryptography' not found.")

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
            raise desec.exceptions.TLSACheckError(
                f"Certificate expired on {cert.not_valid_after_utc}"
            )
        # Check is usage matches the certificate's CA status.
        is_ca_cert = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        if is_ca_cert and usage not in ["PKIX-TA", "DANE-TA"]:
            raise desec.exceptions.TLSACheckError(
                "CA certificate given for end entity usage. Please select a "
                "different certificate or set usage to PKIX-TA or DANE-TA."
            )
        elif not is_ca_cert and usage not in ["PKIX-EE", "DANE-EE"]:
            raise desec.exceptions.TLSACheckError(
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
                raise desec.exceptions.TLSACheckError(
                    f"Certificate is valid for {sans}, but not {target_name}."
                )

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
