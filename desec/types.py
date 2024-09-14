"""Custom type definitions."""

from __future__ import annotations

import typing as t

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
    auto_policy: bool
    created: str
    id: str
    is_valid: bool
    last_used: str | None
    max_age: str | None
    max_unused_period: str | None
    name: str
    perm_create_domain: bool
    perm_delete_domain: bool
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
