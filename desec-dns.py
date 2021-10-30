#!/usr/bin/env python3
# vim: encoding=utf-8
"""Simple API client for desec.io"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from hashlib import sha256, sha512
from pprint import pprint

import requests

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import PublicFormat
    cryptography_available = True
except ModuleNotFoundError:
    cryptography_available = False

api_base_url = 'https://desec.io/api/v1'
record_types = ('A', 'AAAA', 'AFSDB', 'ALIAS', 'CAA', 'CERT', 'CNAME', 'DNAME', 'HINFO', 'KEY',
                'LOC', 'MX', 'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'RP', 'SSHFP', 'SRV', 'TKEY',
                'TSIG', 'TLSA', 'SMIMEA', 'TXT', 'URI')

ERR_INVALID_PARAMETERS = 3
ERR_API = 4
ERR_AUTH = 5
ERR_NOT_FOUND = 6
ERR_TLSA_CHECK = 7
ERR_RATE_LIMIT = 8


class APIError(Exception):
    """Exception for errors returned by the API"""
    error_code = ERR_API


class AuthenticationError(APIError):
    """Exception for authentication failure"""
    error_code = ERR_AUTH


class NotFoundError(APIError):
    """Exception when data can not be found"""
    error_code = ERR_NOT_FOUND


class ParameterError(APIError):
    """Exception for invalid parameters, such as DNS records"""
    error_code = ERR_INVALID_PARAMETERS


class TLSACheckError(APIError):
    """Exception for TLSA record setup sanity check errors"""
    error_code = ERR_TLSA_CHECK


class RateLimitError(APIError):
    """Exception for API rate limits"""
    error_code = ERR_RATE_LIMIT


class TokenAuth(requests.auth.AuthBase):

    """Token-based authentication for requests"""

    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['Authorization'] = 'Token ' + self.token
        return r


class TLSAField(object):

    """Abstract class for TLSA fields that handles numeric values and symbolic names
    interchangably"""

    def __init__(self, value):
        try:
            value = self.valid_values.index(str(value).upper())
        except ValueError:
            pass
        self._value = int(value)
        try:
            self.valid_values[self._value]
        except IndexError:
            self._value = None

    def __eq__(self, other):
        if self._value is None:
            return False
        elif isinstance(other, int):
            return self._value == other
        elif isinstance(other, str):
            return self.valid_values[self._value] == other.upper()
        else:
            return self._value == other._value

    def __repr__(self):
        if self._value is None:
            return ''
        else:
            return self.valid_values[self._value]

    def __int__(self):
        return self._value


class TLSAUsage(TLSAField):
    """TLSA certificate usage information"""
    valid_values = ['PKIX-TA', 'PKIX-EE', 'DANE-TA', 'DANE-EE']


class TLSASelector(TLSAField):
    """TLSA selector"""
    valid_values = ['CERT', 'SPKI']


class TLSAMatchType(TLSAField):
    """TLSA match type"""
    valid_values = ['FULL', 'SHA2-256', 'SHA2-512']


class APIClient(object):

    """deSEC.io API client"""

    def __init__(self, token):
        """
        :token: API authorization token
        """
        self._token_auth = TokenAuth(token)

    def query(self, method, url, data=None):
        """Query the API

        :method: HTTP method to use
        :url: target URL
        :data: data to send
        :returns: (status code, response data)

        """
        if method == 'GET' or method == 'DELETE':
            params = data
            body = None
        else:
            params = None
            body = data
        r = requests.request(method, url, auth=self._token_auth, params=params, json=body)
        if r.status_code == 401:
            raise AuthenticationError()
        elif r.status_code == 429:
            raise RateLimitError(r.json()['detail'])
        try:
            response_data = r.json()
        except ValueError:
            response_data = None
        return (r.status_code, response_data)

    def list_tokens(self):
        """Return a list of all tokens
        See https://desec.readthedocs.io/en/latest/auth/tokens.html#retrieving-all-current-tokens

        :returns: dict containing tokens and information about them

        """
        url = api_base_url + '/auth/tokens/'
        code, data = self.query('GET', url)
        if code == 200:
            return data
        elif code == 403:
            raise APIError('Insufficient permissions to manage tokens')
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def create_token(self, name='', manage_tokens=None):
        """Create a new authenticaion token.
        See https://desec.readthedocs.io/en/latest/auth/tokens.html#create-additional-tokens

        :name: the name of the token
        :manage_tokens: boolean indicating whether the token can manage tokens
        :returns: the newly created token

        """
        url = api_base_url + '/auth/tokens/'
        request_data = {'name': name}
        if manage_tokens is not None:
            request_data['perm_manage_tokens'] = manage_tokens
        code, data = self.query('POST', url, request_data)
        if code == 201:
            return data
        elif code == 403:
            raise APIError('Insufficient permissions to manage tokens')
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def delete_token(self, token_id):
        """Delete an authentication token
        See https://desec.readthedocs.io/en/latest/auth/tokens.html#delete-tokens

        :token_id: the unique id of the token to delete
        :returns: nothing

        """
        url = api_base_url + '/auth/tokens/' + token_id + '/'
        code, data = self.query('DELETE', url)
        if code == 204:
            pass
        elif code == 403:
            raise APIError('Insufficient permissions to manage tokens')
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def list_domains(self):
        """Return a list of all registered domains
        See https://desec.readthedocs.io/en/latest/dns/domains.html#listing-domains

        :returns: list of domain names

        """
        url = api_base_url + '/domains/'
        code, data = self.query('GET', url)
        if code == 200:
            return [domain['name'] for domain in data]
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def domain_info(self, domain):
        """Return basic information about a domain
        See https://desec.readthedocs.io/en/latest/dns/domains.html#retrieving-a-specific-domain

        :domain: domain name
        :returns: dict containing domain information

        """
        url = api_base_url + '/domains/' + domain + '/'
        code, data = self.query('GET', url)
        if code == 200:
            return data
        elif code == 404:
            raise NotFoundError('Domain {} not found'.format(domain))
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def new_domain(self, domain):
        """Create a new domain
        See https://desec.readthedocs.io/en/latest/dns/domains.html#creating-a-domain

        :domain: domain name
        :returns: dict containing domain information

        """
        url = api_base_url + '/domains/'
        code, data = self.query('POST', url, data={'name': domain})
        if code == 201:
            return data
        elif code == 400:
            raise ParameterError('Malformed domain name {}'.format(domain))
        elif code == 403:
            raise APIError('Maximum number of domains reached')
        elif code == 409:
            raise ParameterError('Could not create domain {} ({})'.format(domain, data))
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def delete_domain(self, domain):
        """Delete a domain
        See https://desec.readthedocs.io/en/latest/dns/domains.html#deleting-a-domain

        :domain: domain name
        :returns: nothing

        """
        url = api_base_url + '/domains/' + domain + '/'
        code, data = self.query('DELETE', url)
        if code == 204:
            pass
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def get_records(self, domain, rtype=None, subname=None):
        """Return all records of a domain, possibly restricted to records of type `rtype` and
        subname `subname`
        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#retrieving-all-rrsets-in-a-zone

        :domain: domain name
        :rtype: DNS record type
        :subname: DNS entry name
        :returns: list of dicts representing RRsets

        """
        url = api_base_url + '/domains/' + domain + '/rrsets/'
        code, data = self.query('GET', url,
                                {'subname': subname, 'type': rtype})
        if code == 200:
            return data
        elif code == 404:
            raise NotFoundError('Domain {} not found'.format(domain))
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def add_record(self, domain, rtype, subname, rrset, ttl):
        """Add a new RRset. There must not be a RRset for this domain-type-subname combination
        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#creating-an-rrset

        :domain: domain name
        :rtype: DNS record type
        :subname: DNS entry name
        :rrset: list of DNS record contents
        :ttl: TTL for the DNS entry
        :returns: dict representing the created RRset

        """
        url = api_base_url + '/domains/' + domain + '/rrsets/'
        code, data = self.query('POST', url,
                                {'subname': subname, 'type': rtype, 'records': rrset, 'ttl': ttl})
        if code == 201:
            return data
        elif code == 404:
            raise NotFoundError('Domain {} not found'.format(domain))
        elif code == 422:
            raise ParameterError('Invalid RRset {rrset} for {rtype} record {subname}.{domain}'.
                format(rrset=rrset, rtype=rtype, subname=subname, domain=domain))
        elif code == 400:
            raise APIError('Could not create RRset {rrset} for {rtype} record {subname}.{domain}'.
                           format(rrset=rrset, rtype=rtype, subname=subname, domain=domain))
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def update_bulk_record(self, domain, rrset_list):
        """Update RRsets in bulk.
        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#bulk-operations

        :domain: domain name
        :rrset_list: List of RRsets
        """
        url = api_base_url + '/domains/' + domain + '/rrsets/'
        code, data = self.query('PUT', url, rrset_list)

        if code == 200:
            return data
        elif code == 400:
            raise APIError('Could not create RRsets. Errors: {}'.format(data))
        elif code == 404:
            raise NotFoundError('Domain {} not found'.format(domain))
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def change_record(self, domain, rtype, subname, rrset=None, ttl=None):
        """Change an existing RRset. Existing data is replaced by the provided `rrset` and `ttl`
        (if provided)
        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#modifying-an-rrset

        :domain: domain name
        :rtype: DNS record type
        :subname: DNS entry name
        :rrset: list of DNS record contents
        :ttl: TTL for the DNS entry
        :returns: dict representing the changed RRset

        """
        url = api_base_url + '/domains/' + domain + '/rrsets/' + subname + '.../' + rtype + '/'
        request_data = {}
        if rrset:
            request_data['records'] = rrset
        if ttl:
            request_data['ttl'] = ttl
        code, data = self.query('PATCH', url, data=request_data)
        if code == 200:
            return data
        elif code == 404:
            raise NotFoundError('RRset {rrset} for {rtype} record {subname}.{domain} not found'.
                                format(rrset=rrset, rtype=rtype, subname=subname, domain=domain))
        elif code == 400:
            raise ParameterError(
                'Missing data for changing RRset {rrset} for {rtype} record {subname}.{domain}'.
                format(rrset=rrset, rtype=rtype, subname=subname, domain=domain))
        elif code == 422:
            raise ParameterError('Invalid RRset {rrset} for {rtype} record {subname}.{domain}'.
                format(rrset=rrset, rtype=rtype, subname=subname, domain=domain))
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def delete_record(self, domain, rtype, subname, rrset=None):
        """Delete an existing RRset or records from an RRset
        See https://desec.readthedocs.io/en/latest/dns/rrsets.html#deleting-an-rrset

        :domain: domain name
        :rtype: DNS record type
        :subname: DNS entry name
        :rrset: delete only the records in this rrset and keep any others
                (None means to delete everything)
        :returns: nothing

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
            records_to_keep = [r for r in data['records'] if r not in rrset]
        if records_to_keep:
            # Some records should be kept, use change_record for that
            self.change_record(domain, rtype, subname, records_to_keep)
        else:
            # Nothing should be kept, delete the whole RRset
            url = api_base_url + '/domains/' + domain + '/rrsets/' + subname + '.../' + rtype + '/'
            code, data = self.query('DELETE', url)
            if code == 204:
                pass
            elif code == 404:
                raise NotFoundError('Domain {} not found'.format(domain))
            else:
                raise APIError('Unexpected error code {}'.format(code))

    def update_record(self, domain, rtype, subname, rrset, ttl=None):
        """Change an existing RRset or create a new one. Records are added to the existing records
        (if any). `ttl` is used only when creating a new record sets. For existing records sets,
        the existing TTL is kept.

        :domain: domain name
        :rtype: DNS record type
        :subname: DNS entry name
        :rrset: list of DNS record contents
        :ttl: TTL for the DNS entry
        :returns: dict representing the new RRset

        """
        data = self.get_records(domain, rtype, subname)
        if not data:
            # There is no entry, simply create a new one
            return self.add_record(domain, rtype, subname, rrset, ttl)
        else:
            # Update the existing records with the given ones
            rrset.extend(data[0]['records'])
            return self.change_record(domain, rtype, subname, rrset)


def print_records(rrset, **kwargs):
    """Print a RRset

    :record: the RRset to print
    :**kwargs: additional keyword arguments to print()
    :returns: nothing

    """
    for r in rrset['records']:
        line = ('{rrset[name]} {rrset[ttl]} IN {rrset[type]} {record}'
                .format(rrset=rrset, record=r))
        print(line, **kwargs)


def print_rrsets(rrsets, **kwargs):
    """Print multiple RRsets

    :rrsets: the RRsets to print
    :**kwargs: additional keyword arguments to print()
    :returns: nothing

    """
    for rrset in rrsets:
        print_records(rrset, **kwargs)


def sanitize_records(rtype, subname, rrset):
    """Check the given DNS records for common errors and return a copy with fixed data. Raise an
    Exception if not all errors can be fixed.
    See https://desec.readthedocs.io/en/latest/dns/rrsets.html#notes

    :rtype: DNS record type
    :subname: DNS entry name
    :rrset: list of DNS record contents
    :returns: list of DNS record contents

    """
    if rtype == 'CNAME' and rrset and len(rrset) > 1:
        # Multiple CNAME records in the same rrest are not legal.
        raise ParameterError('Multiple CNAME records are not allowed.')
    if rtype in ('CNAME', 'MX') and rrset:
        # CNAME and MX records must end in a .
        rrset = [r + '.' if r[-1] != '.' else r for r in rrset]
    if rtype == 'CNAME' and subname == '':
        # CNAME in the zone apex can break the zone
        raise ParameterError('CNAME records in the zone apex are not allowed.')
    if (rtype == 'NS' and rrset and any(['*' in r for r in rrset])):
        # Wildcard NS records do not play well with DNSSEC
        raise ParameterError('Wildcard NS records are not allowed.')
    if rtype == 'TXT' and rrset:
        # TXT records must be in ""
        rrset = ['"' + r + '"' if r[0] != '"' or r[-1] != '"' else r for r in rrset]
    return rrset


def tlsa_record(file, usage=TLSAUsage('DANE-EE'), selector=TLSASelector('Cert'),
                match_type=TLSAMatchType('SHA2-256'), check=True, subname=None, domain=None):
    """Return the TLSA record for the given certificate, usage, selector and match_type.
    Raise an Exception if the given parameters do not seem to make sense.

    :file: Path to the X.509 certificate to generate the record for. PEM and DER encoded files work
    :usage: Value of type TLSAUsage. See RFC 6698, Section 2.1.1
    :selector: Value of type TLSASelector. See RFC 6698, Section 2.1.2
    :match_type: Value of type TLSAMatchType. See RFC 6698, Section 2.1.3
    :check: Whether to do sanity checks. Boolean.
    :subname: Subname the TLSA record will be valid for. Only used when `check` is True.
    :domain: Domain the TLSA record will be valid for. Only used when `check` is True.
    :returns: A string containing the rrset data for a TLSA records for the given parameters.

    """
    # Read the certifiate from `file`.
    with open(file, 'rb') as f:
        cert_data = f.read()
    # Parse the certificate.
    if cert_data.startswith(b'-----BEGIN CERTIFICATE-----'):
        # PEM format
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    else:
        # DER format
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

    # Do some sanity checks.
    if check:
        # Check certificate expiration.
        if cert.not_valid_after <= datetime.utcnow():
            raise TLSACheckError('Certificate expired on {}'.format(cert.not_valid_after))
        # Check is usage matches the certificate's CA status.
        is_ca_cert = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        if (is_ca_cert and usage not in ['PKIX-TA', 'DANE-TA']):
            raise TLSACheckError('CA certificate given for end entity usage. Please select a '
                                 'different certificate or set usage to PKIX-TA or DANE-TA.')
        elif (not is_ca_cert and usage not in ['PKIX-EE', 'DANE-EE']):
            raise TLSACheckError('Non-CA certificate given for CA usage. Please select a '
                                 'different certificate or set usage to PKIX-EE or DANE-EE.')
        # Check if any SAN matches the subname + domain
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if domain is not None:
            if subname:
                target_name = subname + '.' + domain
            else:
                target_name = domain
            for name in san.value.get_values_for_type(x509.DNSName):
                if name == target_name:
                    break
            else:
                raise TLSACheckError('Certificate is valid for {sans}, but not {target_name}.'
                    .format(sans=', '.join(san.value.get_values_for_type(x509.DNSName)),
                            target_name=target_name))

    # Determine what to put in the TLSA record.
    if selector == 'SPKI':
        # Only the DER encoded public key.
        data = cert.public_key().public_bytes(encoding=Encoding.DER,
                                              format=PublicFormat.SubjectPublicKeyInfo)
    else:
        # Full DER encoded certificate.
        data = cert.public_bytes(encoding=Encoding.DER)

    # Encode the data.
    if match_type == 'Full':
        data = data.hex()
    elif match_type == 'SHA2-256':
        data = sha256(data).hexdigest()
    elif match_type == 'SHA2-512':
        data = sha512(data).hexdigest()

    return '{} {} {} {}'.format(int(usage), int(selector), int(match_type), data)


def main():
    parser = argparse.ArgumentParser(
        description='A simple deSEC.io API client')
    action = parser.add_subparsers(dest='action', metavar='action')
    action.required = True

    token = parser.add_mutually_exclusive_group()
    token.add_argument('--token', help='API authentication token')
    token.add_argument('--token-file',
        default=os.path.join(os.path.expanduser('~'), '.desec_auth_token'),
        help='file containing the API authentication token (default: %(default)s)')

    p = action.add_parser('list-tokens', help='list all authentication tokens')

    p = action.add_parser('create-token', help='create and return a new authentication token')
    p.add_argument('--name', default='', help='token name')
    p.add_argument('--manage-tokens', action='store_true', default=False,
                   help='create a token that can manage tokens')

    p = action.add_parser('delete-token', help='delete an authentication token')
    p.add_argument('id', help='token d')

    p = action.add_parser('list-domains', help='list all registered domains')

    p = action.add_parser('domain-info', help='get information about a domain')
    p.add_argument('domain', help='domain name')

    p = action.add_parser('new-domain', help='create a new domain')
    p.add_argument('domain', help='domain name')

    p = action.add_parser('delete-domain', help='delete a domain')
    p.add_argument('domain', help='domain name')

    p = action.add_parser('get-records', help='list all records of a domain')
    p.add_argument('domain', help='domain name')
    p.add_argument('-t', '--type', choices=record_types, metavar='TYPE',
        help='list only records of the given type')
    p.add_argument('-s', '--subname', help='list only records for the given subname')

    p = action.add_parser('add-record', help='add a record set to the domain')
    p.add_argument('domain', help='domain name')
    p.add_argument('-t', '--type', choices=record_types, metavar='TYPE', required=True,
        help='record type to add')
    p.add_argument('-s', '--subname', default='',
        help='subname to add, omit to add a record to the zone apex')
    p.add_argument('-r', '--records', required=True, nargs='+', metavar='RECORD',
        help='the DNS record(s) to add')
    p.add_argument('--ttl', type=int, default=3600,
        help='set the record\'s TTL (default: %(default)i seconds)')

    p = action.add_parser('change-record', help='change an existing record set')
    p.add_argument('domain', help='domain name')
    p.add_argument('-t', '--type', choices=record_types, metavar='TYPE', required=True,
        help='record type to change')
    p.add_argument('-s', '--subname', default='',
        help='subname to change, omit to change a record in the zone apex')
    p.add_argument('-r', '--records', nargs='+', metavar='RECORD', help='the new DNS record(s)')
    p.add_argument('--ttl', type=int, help='the new TTL')

    p = action.add_parser('delete-record', help='delete a record set')
    p.add_argument('domain', help='domain name')
    p.add_argument('-t', '--type', choices=record_types, metavar='TYPE', required=True,
        help='record type to delete')
    p.add_argument('-s', '--subname', default='',
        help='subname to delete, omit to delete a record from the zone apex')
    p.add_argument('-r', '--records', nargs='+', metavar='RECORD',
        help='the DNS records to delete (default: all)')

    p = action.add_parser('update-record',
        help='add entries, possibly to an existing record set')
    p.add_argument('domain', help='domain name')
    p.add_argument('-t', '--type', choices=record_types, metavar='TYPE', required=True,
        help='record type to add')
    p.add_argument('-s', '--subname', default='',
        help='subname to add, omit to add a record to the zone apex')
    p.add_argument('-r', '--records', nargs='+', required=True, metavar='RECORD',
        help='the DNS records to add')
    p.add_argument('--ttl', type=int, default=3600,
        help='set the record\'s TTL, if creating a new record set (default: %(default)i seconds)')

    if cryptography_available:
        p = action.add_parser('add-tlsa',
            help='add a TLSA record for a X.509 certificate (aka DANE), keeping any existing '
                 'records')
        p.add_argument('domain', help='domain name')
        p.add_argument('-s', '--subname', default='',
            help='subname that the record is valid for, omit to set a record to the zone apex')
        p.add_argument('-p', '--ports', nargs='+', required=True,
            help='ports that use the certificate')
        p.add_argument('--protocol', choices=['tcp', 'udp', 'sctp'], default='tcp',
            help='protocol that the given ports use (default: %(default)s)')
        p.add_argument('-c', '--certificate', required=True,
            help='file name of the X.509 certificate for which to set TLSA records (DER or PEM '
                 'format)')
        p.add_argument('--usage', type=TLSAUsage, default=TLSAUsage('DANE-EE'),
            choices=['PKIX-TA', 'PKIX-EE', 'DANE-TA', 'DANE-EE'],
            help='TLSA certificate usage information. Accepts numeric values or RFC 7218 symbolic '
                 'names (default: %(default)s)')
        p.add_argument('--selector', type=TLSASelector, default=TLSASelector('Cert'),
            choices=['Cert', 'SPKI'],
            help='TLSA selector. Accepts numeric values or RFC 7218 symbolic names '
                 '(default: %(default)s)')
        p.add_argument('--match-type', type=TLSAMatchType, default=TLSAMatchType('SHA2-256'),
            choices=['Full', 'SHA2-256', 'SHA2-512'],
            help='TLSA matching type. Accepts numeric values or RFC 7218 symbolic names '
                 '(default: %(default)s)')
        p.add_argument('--ttl', type=int, default=3600,
            help='set the record\'s TTL, if creating a new record set '
                 '(default: %(default)i seconds)')
        p.add_argument('--no-check', action='store_false', dest='check', default=True,
            help='skip any sanity checks and set the TLSA record as specified')

        p = action.add_parser('set-tlsa',
            help='set the TLSA record for a X.509 certificate (aka DANE), removing any existing '
                 'records for the same port, protocol and subname')
        p.add_argument('domain', help='domain name')
        p.add_argument('-s', '--subname', default='',
            help='subname that the record is valid for, omit to set a record to the zone apex')
        p.add_argument('-p', '--ports', nargs='+', required=True,
            help='ports that use the certificate')
        p.add_argument('--protocol', choices=['tcp', 'udp', 'sctp'], default='tcp',
            help='protocol that the given ports use (default: %(default)s)')
        p.add_argument('-c', '--certificate', required=True,
            help='file name of the X.509 certificate for which to set TLSA records (DER or PEM '
                 'format)')
        p.add_argument('--usage', type=TLSAUsage, default=TLSAUsage('DANE-EE'),
            choices=['PKIX-TA', 'PKIX-EE', 'DANE-TA', 'DANE-EE'],
            help='TLSA certificate usage information. Accepts numeric values or RFC 7218 symbolic '
                 'names (default: %(default)s)')
        p.add_argument('--selector', type=TLSASelector, default=TLSASelector('Cert'),
            choices=['Cert', 'SPKI'],
            help='TLSA selector. Accepts numeric values or RFC 7218 symbolic names '
                 '(default: %(default)s)')
        p.add_argument('--match-type', type=TLSAMatchType, default=TLSAMatchType('SHA2-256'),
            choices=['Full', 'SHA2-256', 'SHA2-512'],
            help='TLSA matching type. Accepts numeric values or RFC 7218 symbolic names '
                 '(default: %(default)s)')
        p.add_argument('--ttl', type=int, default=3600,
            help='set the record\'s TTL, if creating a new record set '
                 '(default: %(default)i seconds)')
        p.add_argument('--no-check', action='store_false', dest='check', default=True,
            help='skip any sanity checks and set the TLSA record as specified')

    p = action.add_parser('export', help='export all records into a file')
    p.add_argument('domain', help='domain name')
    p.add_argument('-f', '--file', required=True, help='target file name')

    p = action.add_parser('import', help='import records from a file')
    p.add_argument('domain', help='domain name')
    p.add_argument('-f', '--file', required=True, help='target file name')
    p.add_argument('--clear', action='store_true',
                   help='remove all existing records before import')

    p = action.add_parser('import-zone', help='import records from a zone file')
    p.add_argument('domain', help='domain name')
    p.add_argument('-f', '--file', required=True, help='target file name')
    p.add_argument('-d', '--dry-run', action='store_true',
                   help='just parse zone data, but do not write it to the API')

    arguments = parser.parse_args()
    del action, token, p, parser

    if arguments.token:
        api_client = APIClient(arguments.token)
    else:
        with open(arguments.token_file, 'r') as f:
            api_client = APIClient(f.readline().strip())

    try:

        if arguments.action == 'list-tokens':

            tokens = api_client.list_tokens()
            pprint(tokens)

        elif arguments.action == 'create-token':

            data = api_client.create_token(arguments.name, arguments.manage_tokens)
            print(data['token'])

        elif arguments.action == 'delete-token':

            data = api_client.delete_token(arguments.id)

        elif arguments.action == 'list-domains':

            domains = api_client.list_domains()
            for d in domains:
                print(d)

        elif arguments.action == 'domain-info':

            data = api_client.domain_info(arguments.domain)
            pprint(data)

        elif arguments.action == 'new-domain':

            data = api_client.new_domain(arguments.domain)
            pprint(data)

        elif arguments.action == 'delete-domain':

            api_client.delete_domain(arguments.domain)

        elif arguments.action == 'get-records':

            data = api_client.get_records(arguments.domain, arguments.type, arguments.subname)
            for rrset in data:
                print_records(rrset)

        elif arguments.action == 'add-record':

            arguments.records = sanitize_records(arguments.type, arguments.subname,
                                                 arguments.records)
            data = api_client.add_record(arguments.domain, arguments.type, arguments.subname,
                                         arguments.records, arguments.ttl)
            print_records(data)

        elif arguments.action == 'change-record':

            arguments.records = sanitize_records(arguments.type, arguments.subname,
                                                 arguments.records)
            data = api_client.change_record(arguments.domain, arguments.type, arguments.subname,
                                            arguments.records, arguments.ttl)
            print_records(data)

        elif arguments.action == 'update-record':

            arguments.records = sanitize_records(arguments.type, arguments.subname,
                                                 arguments.records)
            data = api_client.update_record(arguments.domain, arguments.type, arguments.subname,
                                            arguments.records, arguments.ttl)
            print_records(data)

        elif arguments.action == 'delete-record':

            if arguments.records:
                arguments.records = sanitize_records(arguments.type, arguments.subname,
                                                     arguments.records)
            api_client.delete_record(arguments.domain, arguments.type, arguments.subname,
                                     arguments.records)

        elif arguments.action == 'add-tlsa' or arguments.action == 'set-tlsa':

            record = tlsa_record(arguments.certificate, arguments.usage, arguments.selector,
                                 arguments.match_type, arguments.check, arguments.subname,
                                 arguments.domain)

            for port in arguments.ports:
                subname = '_{port}._{protocol}.{subname}'.format(port=port,
                                                                 protocol=arguments.protocol,
                                                                 subname=arguments.subname)
                if arguments.action == 'add-tlsa':
                    data = api_client.update_record(arguments.domain, 'TLSA', subname, [record],
                                                    arguments.ttl)
                elif arguments.action == 'set-tlsa':
                    if not api_client.get_records(arguments.domain, 'TLSA', subname):
                        data = api_client.add_record(arguments.domain, 'TLSA', subname, [record],
                                                     arguments.ttl)
                    else:
                        data = api_client.change_record(arguments.domain, 'TLSA', subname,
                                                        [record], arguments.ttl)
                print_records(data)

        elif arguments.action == 'export':

            data = api_client.get_records(arguments.domain)
            # Write the data to the export file in json format
            with open(arguments.file, 'w') as f:
                json.dump(data, f)

        elif arguments.action == 'import':

            with open(arguments.file, 'r') as f:
                records = json.load(f)
            # Create the domain if it does not exist.
            try:
                api_client.domain_info(arguments.domain)
            except NotFoundError:
                api_client.new_domain(arguments.domain)
            if arguments.clear:
                # Delete all existing records:
                for r in api_client.get_records(arguments.domain):
                    api_client.delete_record(arguments.domain, r['type'], r['subname'])
                existing_records = []
            else:
                existing_records = api_client.get_records(arguments.domain)
            # Add the imported records.
            for r in records:
                if any([r['type'] == x['type'] and r['subname'] == x['subname']
                        for x in existing_records]):
                    # The record set already exists, change it to match the
                    # imported data.
                    api_client.change_record(arguments.domain, r['type'], r['subname'],
                                             r['records'], r['ttl'])
                else:
                    # There is no record set with the given type and subname,
                    # add a new one.
                    api_client.add_record(arguments.domain, r['type'], r['subname'],
                                          r['records'], r['ttl'])

        elif arguments.action == 'import-zone':

            with open(arguments.file, 'r') as f:
                # Regex to parse a line of a zone file.
                entry_regex = re.compile(
                    r'''^(?P<name>.*?\.)\s+
                    (?P<ttl>[0-9]{3,5})\s+
                    IN\s+
                    (?P<type>[A-Z0-9]+)\s+
                    (?P<record>.*)$''',
                    re.VERBOSE)

                # Parse the zone file into a (temporary) dict.
                record_dict = {}
                for line in f.readlines():
                    # Skip comments.
                    if line.startswith(';'):
                        continue

                    # Parse a line.
                    matches = entry_regex.match(line)
                    subname = (matches.group("name").removesuffix(arguments.domain + ".")
                               .removesuffix("."))
                    ttl = int(matches.group("ttl"))
                    rtype = matches.group("type")
                    record = matches.group("record")

                    if rtype not in record_types:
                        print(f'Record type {rtype} not supported, skipping...', file=sys.stderr)
                        continue

                    if ttl < 3600:
                        print('TTL smaller than minimum of 3600 seconds, adjusting.',
                              file=sys.stderr)
                        ttl = 3600

                    records = sanitize_records(rtype, subname, [record])

                    # Place the record in a dict.
                    # The key is used for merging entries of the same type.
                    key = (subname, rtype, ttl)
                    # If there is another entry with the same key, add the current record to the
                    # list and save the entry.
                    entry = record_dict.get(key, [])
                    entry.extend(records)
                    record_dict[key] = entry

                # Convert the dict back to a list for interacting with the API.
                record_list = []
                for k, v in record_dict.items():
                    subname, rtype, ttl = k
                    record_list.append({'subname': subname, 'type': rtype, 'records': v,
                                        'ttl': ttl})

                if arguments.dry_run:
                    print("Dry run. Not writing changes to API. I would have written this:",
                          file=sys.stderr)
                    pprint(record_list)
                else:
                    data = api_client.update_bulk_record(arguments.domain, record_list)
                    print_rrsets(data)

    except AuthenticationError as e:
        print('Invalid token.')
        sys.exit(e.error_code)
    except APIError as e:
        print(str(e))
        sys.exit(e.error_code)


if __name__ == "__main__":
    main()
