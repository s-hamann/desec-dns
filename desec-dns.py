#!/usr/bin/env python3
# vim: encoding=utf-8
"""Simple API client for desec.io"""

import argparse
import json
import os
import sys
from pprint import pprint

import requests


api_base_url = 'https://desec.io/api/v1'
record_types = ('A', 'AAAA', 'AFSDB', 'ALIAS', 'CAA', 'CERT', 'CNAME', 'DNAME', 'HINFO', 'KEY',
                'LOC', 'MX', 'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'RP', 'SSHFP', 'SRV', 'TKEY',
                'TSIG', 'TLSA', 'SMIMEA', 'TXT', 'URI')

ERR_INVALID_PARAMETERS = 3
ERR_API = 4
ERR_AUTH = 5
ERR_NOT_FOUND = 6


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


class TokenAuth(requests.auth.AuthBase):

    """Token-based authentication for requests"""

    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['Authorization'] = 'Token ' + self.token
        return r


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
        else:
            raise APIError('Unexpected error code {}'.format(code))

    def create_token(self, name=''):
        """Create a new authenticaion token.
        See https://desec.readthedocs.io/en/latest/auth/tokens.html#create-additional-tokens

        :name: the name of the token
        :returns: the newly created token

        """
        url = api_base_url + '/auth/tokens/'
        code, data = self.query('POST', url, {'name': name})
        if code == 201:
            return data
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

    p = action.add_parser('export', help='export all records into a file')
    p.add_argument('domain', help='domain name')
    p.add_argument('-f', '--file', required=True, help='target file name')

    p = action.add_parser('import', help='import records from a file')
    p.add_argument('domain', help='domain name')
    p.add_argument('-f', '--file', required=True, help='target file name')
    p.add_argument('--clear', action='store_true',
        help='remove all existing records before import')

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

            data = api_client.create_token(arguments.name)
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

    except AuthenticationError as e:
        print('Invalid token.')
        sys.exit(e.error_code)
    except APIError as e:
        print(str(e))
        sys.exit(e.error_code)


if __name__ == "__main__":
    main()
