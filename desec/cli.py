"""Simple API client for desec.io.

This is the CLI component.
For more information, run 'desec --help'.

Note that the `cli` submodule is not part of the public API and may change without further
notice.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import typing as t
from pprint import pprint

import desec
import desec.api
import desec.exceptions
import desec.tlsa
import desec.types
import desec.utils

# Importing from this submodule is discouraged as it is not part of the package's public
# API. Set __all__ to the empty list to reflect that.
__all__: t.Sequence[str] = []


def print_records(
    rrset: desec.types.JsonRRsetType | desec.types.JsonRRsetFromZonefileType, **kwargs: t.Any
) -> None:
    """Print a RRset in zone file format.

    Args:
        rrset: The RRset to print.
        **kwargs: Additional keyword arguments to print().

    """
    for record in rrset["records"]:
        line = f"{rrset['name']} {rrset['ttl']} IN {rrset['type']} {record}"
        print(line, **kwargs)


def print_rrsets(
    rrsets: t.Sequence[desec.types.JsonRRsetType | desec.types.JsonRRsetFromZonefileType],
    **kwargs: t.Any,
) -> None:
    """Print multiple RRsets in zone file format.

    Args:
        rrsets: The RRsets to print.
        **kwargs: Additional keyword arguments to print().

    """
    for rrset in rrsets:
        print_records(rrset, **kwargs)


class CliClientFormatter(logging.Formatter):
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


def configure_cli_logging(level: int) -> None:
    """Set up logging configuration when using the module as a command-line interface.

    Args:
        level: Logging level to set for desec.client logger.
    """
    http_handler = logging.StreamHandler(stream=sys.stderr)
    http_formatter = CliClientFormatter()
    http_handler.setFormatter(http_formatter)
    http_logger = logging.getLogger("desec.client")
    http_logger.addHandler(http_handler)
    http_logger.setLevel(level)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(prog="desec", description="A simple deSEC.io API client")
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {desec.__version__}"
    )
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
    p.add_argument(
        "--create-domain",
        action="store_true",
        default=False,
        help="create a token that can create new domains",
    )
    p.add_argument(
        "--delete-domain",
        action="store_true",
        default=False,
        help="create a token that can delete domains",
    )
    p.add_argument(
        "--allowed-subnets",
        action="append",
        help="IPv4/IPv6 addresses or subnets from which clients may authenticate with this token",
    )
    p.add_argument(
        "--auto-policy",
        action="store_true",
        help="automatically set up a permissive policy for any domains created with this token",
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
    p.add_argument(
        "--create-domain",
        action="store_true",
        default=None,
        help="allow this token to create new domains",
    )
    p.add_argument(
        "--no-create-domain",
        dest="create_domain",
        action="store_false",
        default=None,
        help="do not allow this token to create new domains",
    )
    p.add_argument(
        "--delete-domain",
        action="store_true",
        default=None,
        help="allow this token to delete domains",
    )
    p.add_argument(
        "--no-delete-domain",
        dest="delete_domain",
        action="store_false",
        default=None,
        help="do not allow this token to delete domains",
    )
    p.add_argument(
        "--allowed-subnets",
        action="append",
        help="IPv4/IPv6 addresses or subnets from which clients may authenticate with this token",
    )
    p.add_argument(
        "--auto-policy",
        action="store_true",
        default=None,
        help="automatically set up a permissive policy for any domains created with this token",
    )
    p.add_argument(
        "--no-auto-policy",
        dest="auto_policy",
        action="store_false",
        default=None,
        help="do not automatically set up a policy for any domains created with this token",
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
        choices=desec.RECORD_TYPES,
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
        choices=desec.RECORD_TYPES,
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
        choices=desec.RECORD_TYPES,
        metavar="TYPE",
        help="list only records of the given type",
    )
    p.add_argument("-s", "--subname", help="list only records for the given subname")

    p = p_action.add_parser("add-record", help="add a record set to the domain")
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=desec.RECORD_TYPES,
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
        action="append",
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
        choices=desec.RECORD_TYPES,
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
    p.add_argument(
        "-r", "--records", action="append", metavar="RECORD", help="the new DNS record(s)"
    )
    p.add_argument("--ttl", type=int, help="the new TTL")

    p = p_action.add_parser("delete-record", help="delete a record set")
    p.add_argument("domain", help="domain name")
    p.add_argument(
        "-t",
        "--type",
        choices=desec.RECORD_TYPES,
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
        action="append",
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
        choices=desec.RECORD_TYPES,
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
        action="append",
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

    if desec.tlsa.CRYPTOGRAPHY_AVAILABLE:
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
            "-p", "--ports", action="append", required=True, help="ports that use the certificate"
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
            type=desec.tlsa.TLSAUsage,
            default=desec.tlsa.TLSAUsage("DANE-EE"),
            choices=[
                desec.tlsa.TLSAUsage("PKIX-TA"),
                desec.tlsa.TLSAUsage("PKIX-EE"),
                desec.tlsa.TLSAUsage("DANE-TA"),
                desec.tlsa.TLSAUsage("DANE-EE"),
            ],
            help="TLSA certificate usage information. Accepts numeric values or RFC 7218 symbolic "
            "names (default: %(default)s)",
        )
        p.add_argument(
            "--selector",
            type=desec.tlsa.TLSASelector,
            default=desec.tlsa.TLSASelector("Cert"),
            choices=[desec.tlsa.TLSASelector("Cert"), desec.tlsa.TLSASelector("SPKI")],
            help="TLSA selector. Accepts numeric values or RFC 7218 symbolic names "
            "(default: %(default)s)",
        )
        p.add_argument(
            "--match-type",
            type=desec.tlsa.TLSAMatchType,
            default=desec.tlsa.TLSAMatchType("SHA2-256"),
            choices=[
                desec.tlsa.TLSAMatchType("Full"),
                desec.tlsa.TLSAMatchType("SHA2-256"),
                desec.tlsa.TLSAMatchType("SHA2-512"),
            ],
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
            "-p", "--ports", action="append", required=True, help="ports that use the certificate"
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
            type=desec.tlsa.TLSAUsage,
            default=desec.tlsa.TLSAUsage("DANE-EE"),
            choices=[
                desec.tlsa.TLSAUsage("PKIX-TA"),
                desec.tlsa.TLSAUsage("PKIX-EE"),
                desec.tlsa.TLSAUsage("DANE-TA"),
                desec.tlsa.TLSAUsage("DANE-EE"),
            ],
            help="TLSA certificate usage information. Accepts numeric values or RFC 7218 symbolic "
            "names (default: %(default)s)",
        )
        p.add_argument(
            "--selector",
            type=desec.tlsa.TLSASelector,
            default=desec.tlsa.TLSASelector("Cert"),
            choices=[desec.tlsa.TLSASelector("Cert"), desec.tlsa.TLSASelector("SPKI")],
            help="TLSA selector. Accepts numeric values or RFC 7218 symbolic names "
            "(default: %(default)s)",
        )
        p.add_argument(
            "--match-type",
            type=desec.tlsa.TLSAMatchType,
            default=desec.tlsa.TLSAMatchType("SHA2-256"),
            choices=[
                desec.tlsa.TLSAMatchType("Full"),
                desec.tlsa.TLSAMatchType("SHA2-256"),
                desec.tlsa.TLSAMatchType("SHA2-512"),
            ],
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

    if desec.utils.DNSPYTHON_AVAILABLE:
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
    configure_cli_logging(level=logging.DEBUG if arguments.debug_http else logging.INFO)

    if arguments.token:
        token = arguments.token
    else:
        with open(os.path.expanduser(arguments.token_file)) as f:
            token = f.readline().strip()
    if arguments.block:
        api_client = desec.api.APIClient(token)
    else:
        api_client = desec.api.APIClient(token, retry_limit=0)
    del token

    try:
        if arguments.action == "list-tokens":
            tokens_result = api_client.list_tokens()
            pprint(tokens_result)

        elif arguments.action == "create-token":
            new_token_result = api_client.create_token(
                arguments.name,
                arguments.manage_tokens,
                arguments.create_domain,
                arguments.delete_domain,
                arguments.allowed_subnets,
                arguments.auto_policy,
            )
            print(new_token_result["token"])

        elif arguments.action == "modify-token":
            token_result = api_client.modify_token(
                arguments.id,
                arguments.name,
                arguments.manage_tokens,
                arguments.create_domain,
                arguments.delete_domain,
                arguments.allowed_subnets,
                arguments.auto_policy,
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
                print_records(rrset)

        elif arguments.action == "add-record":
            arguments.records = desec.utils.sanitize_records(
                arguments.type, arguments.subname, arguments.records
            )
            rrset_result = api_client.add_record(
                arguments.domain,
                arguments.type,
                arguments.subname,
                arguments.records,
                arguments.ttl,
            )
            print_records(rrset_result)

        elif arguments.action == "change-record":
            arguments.records = desec.utils.sanitize_records(
                arguments.type, arguments.subname, arguments.records
            )
            rrset_result = api_client.change_record(
                arguments.domain,
                arguments.type,
                arguments.subname,
                arguments.records,
                arguments.ttl,
            )
            print_records(rrset_result)

        elif arguments.action == "update-record":
            arguments.records = desec.utils.sanitize_records(
                arguments.type, arguments.subname, arguments.records
            )
            rrset_result = api_client.update_record(
                arguments.domain,
                arguments.type,
                arguments.subname,
                arguments.records,
                arguments.ttl,
            )
            print_records(rrset_result)

        elif arguments.action == "delete-record":
            if arguments.records:
                arguments.records = desec.utils.sanitize_records(
                    arguments.type, arguments.subname, arguments.records
                )
            api_client.delete_record(
                arguments.domain, arguments.type, arguments.subname, arguments.records
            )

        elif arguments.action == "add-tlsa" or arguments.action == "set-tlsa":
            record = desec.tlsa.tlsa_record(
                arguments.certificate,
                arguments.usage,
                arguments.selector,
                arguments.match_type,
                arguments.check,
                arguments.subname,
                arguments.domain,
            )

            records: list[desec.types.JsonRRsetWritableType]
            records = []
            for port in arguments.ports:
                subname = f"_{port}._{arguments.protocol}"
                if arguments.subname:
                    subname += f".{arguments.subname}"
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
            print_rrsets(rrsets_result)

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
            except desec.exceptions.NotFoundError:
                api_client.new_domain(arguments.domain)

            rrsets_result = api_client.update_bulk_record(
                arguments.domain, records, arguments.clear
            )
            print_rrsets(rrsets_result)

        elif arguments.action == "import-zone":
            record_list = desec.parse_zone_file(
                arguments.file,
                arguments.domain,
                api_client.domain_info(arguments.domain)["minimum_ttl"],
            )
            for entry in record_list:
                if "error_msg" in entry:
                    error_action = "Corrected" if entry["error_recovered"] else "Skipped"
                    print(f"{entry['error_msg']} {error_action}.", file=sys.stderr)
            record_list = desec.clear_errors_from_record_list(record_list)

            if arguments.dry_run:
                print(
                    "Dry run. Not writing changes to API. I would have written this:",
                    file=sys.stderr,
                )
                print_rrsets(record_list)
            else:
                rrsets_result = api_client.update_bulk_record(
                    arguments.domain, record_list, arguments.clear
                )
                print_rrsets(rrsets_result)

    except desec.exceptions.DesecClientError as e:
        print(str(e))
        sys.exit(e.error_code)


if __name__ == "__main__":
    main()
