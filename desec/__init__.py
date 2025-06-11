"""Simple API client for desec.io.

It consists of a python module and a CLI tool.
For more information on the CLI, run 'desec --help'.
For more information on the module's classes and functions, refer to the respective
docstrings.
"""

from __future__ import annotations

import typing as t
from datetime import datetime, timezone
from hashlib import sha256, sha512

import desec.exceptions
import desec.types

# For backwards compatibility, we import submodule content into the top-level scope.
# To be removed in version 2.0.
from desec.api import *  # noqa: F403
from desec.exceptions import *  # noqa: F403
from desec.types import *  # noqa: F403

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


RECORD_TYPES = t.get_args(desec.types.DnsRecordTypeType)


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


def sanitize_records(
    rtype: desec.types.DnsRecordTypeType, subname: str, rrset: list[str]
) -> list[str]:
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
        raise desec.exceptions.ParameterCheckError("Multiple CNAME records are not allowed.")
    if rtype in ("CNAME", "MX", "NS") and rrset:
        # CNAME and MX records must end in a .
        rrset = [r + "." if r[-1] != "." else r for r in rrset]
    if rtype == "CNAME" and subname == "":
        # CNAME in the zone apex can break the zone
        raise desec.exceptions.ParameterCheckError(
            "CNAME records in the zone apex are not allowed."
        )
    if rtype == "NS" and "*" in subname:
        # Wildcard NS records do not play well with DNSSEC
        raise desec.exceptions.ParameterCheckError("Wildcard NS records are not allowed.")
    if rtype == "TXT" and rrset:
        # TXT records must be in ""
        rrset = [f'"{r}"' if r[0] != '"' or r[-1] != '"' else r for r in rrset]
    return rrset


def parse_zone_file(
    path: str | pathlib.Path, domain: str, minimum_ttl: int = 3600
) -> list[desec.types.JsonRRsetFromZonefileType]:
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
    record_list: list[desec.types.JsonRRsetFromZonefileType]
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
                t.cast("desec.types.DnsRecordTypeType", rdatatype.to_text(rrset.rdtype)),
                subname,
                records,
            )
        except desec.exceptions.ParameterCheckError as e:
            error = {"error_msg": str(e), "error_recovered": False}

        entry: desec.types.JsonRRsetFromZonefileType
        entry = {
            "name": f"{subname}.{domain}.",
            "subname": subname,
            "type": t.cast("desec.types.DnsRecordTypeType", rdatatype.to_text(rrset.rdtype)),
            "records": records,
            "ttl": rrset.ttl,
        }
        if error is not None:
            entry.update(error)
        record_list.append(entry)

    return record_list


def clear_errors_from_record_list(
    record_list: t.Sequence[desec.types.JsonRRsetFromZonefileType],
) -> list[desec.types.JsonRRsetFromZonefileType]:
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
