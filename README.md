deSEC.io API client
===================

This is a simple client to manage domains hosted by
[deSEC.io](https://desec.io/) using the deSEC.io API.
It can be used from the command line or as a Python module.

Requirements
============

* Python 3.4+ (may also work with Python 2.7)
* [requests](https://github.com/requests/requests)

Usage
=====

The functionality is split into subcommands, as shown below.
Most subcommand require further parameters to work.
They are described by the usage information of each individual subcommand.

```
usage: desec-dns.py [-h] [--token TOKEN | --token-file TOKEN_FILE] action ...

A simple deSEC.io API client

positional arguments:
  action
    list-domains        list all registered domains
    domain-info         get information about a domain
    new-domain          create a new domain
    delete-domain       delete a domain
    get-records         list all records of a domain
    add-record          add a record set to the domain
    change-record       change an existing record set
    delete-record       delete a record set
    update-record       add entries, possibly to an existing record set
    export              export all records into a file
    import              import records from a file

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN         API authentication token
  --token-file TOKEN_FILE
                        file containing the API authentication token (default:
                        $HOME/.desec_auth_token)
```

Related Work
============

* [deSEC.io - official website](https://desec.io/)
* [deSEC.io DNS API documentation](https://desec.io/docs.html)
* [deSEC.io stack](https://github.com/desec-io/desec-stack)
* [deSEC.io API client](https://github.com/gerhard-tinned/desec-dns-api-cli)
* [acmetool hook for DNS-based domain verification with deSEC.io](https://gist.github.com/s-hamann/e099bf0432f5c7f507e967b00b551e82)
