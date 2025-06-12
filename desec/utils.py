"""Miscellaneous utility functions."""

from __future__ import annotations

import typing as t

import desec
import desec.exceptions
import desec.types

DNSPYTHON_AVAILABLE = False
"""Whether the `dns` (dnspython) module can be imported. Functionality is limited if it is
not available."""

try:
    import dns.name
    from dns import rdatatype, zone

    DNSPYTHON_AVAILABLE = True
except ModuleNotFoundError:
    pass

if t.TYPE_CHECKING:
    import pathlib


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
        desec.exceptions.ParameterCheckError: An unfixable error was found.

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

    Note: This function requires the `dns` (dnspython) module.

    Args:
        path: Path to the zone file to parse.
        domain: The domain name of all records in the zone file.
        minimum_ttl: The Minimum TTL value for records in the target domain.

    Returns:
        A list of dictionaries describing the DNS records in the zone file with additional
        error information for records with errors.

    Raises:
        ModuleNotFoundError: The `dns` module could not be imported (on import of this
            module).

    """
    if not DNSPYTHON_AVAILABLE:  # pragma: no cover
        raise ModuleNotFoundError("Module 'dns' not found.")

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

        if rdatatype.to_text(rrset.rdtype) not in desec.RECORD_TYPES:
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
