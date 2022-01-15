deSEC.io API client
===================

This is a simple client to manage domains hosted by
[deSEC.io](https://desec.io/) using the deSEC.io API.
It can be used from the command line or as a Python module.

Requirements
============

* Python 3.9+
* [requests](https://github.com/requests/requests)
* [cryptography](https://github.com/pyca/cryptography/) (optional, for high-level management of TLSA records)

Usage
=====

The functionality is split into subcommands, as shown below.
Most subcommand require further parameters to work.
They are described by the usage information of each individual subcommand.

```
usage: desec.py [-h] [--token TOKEN | --token-file TOKEN_FILE] action ...

A simple deSEC.io API client

positional arguments:
  action
    list-tokens         list all authentication tokens
    create-token        create and return a new authentication token
    modify-token        modify an existing authentication token
    delete-token        delete an authentication token
    list-token-domain-policies
                        list all domain policies of an authentication token
    add-token-domain-policy
                        add a domain policy for an authentication token
    modify-token-domain-policy
                        modify an existing domain policy for an authentication token
    list-domains        list all registered domains
    domain-info         get information about a domain
    new-domain          create a new domain
    delete-domain       delete a domain
    get-records         list all records of a domain
    add-record          add a record set to the domain
    change-record       change an existing record set
    delete-record       delete a record set
    update-record       add entries, possibly to an existing record set
    add-tlsa            add a TLSA record for a X.509 certificate (aka DANE),
                        keeping any existing records
    set-tlsa            set the TLSA record for a X.509 certificate (aka
                        DANE), removing any existing records for the same
                        port, protocol and subname
    export              export all records into a file
    import              import records from a file
    import-zone         import records from a zone file

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN         API authentication token
  --token-file TOKEN_FILE
                        file containing the API authentication token (default:
                        $HOME/.desec_auth_token)
  --non-blocking        When the API's rate limit is reached, return an
                        appropriate error.
  --blocking            When the API's rate limit is reached, wait and retry
                        the request. This is the default behaviour.
```

Related Work
============

* [deSEC.io - official website](https://desec.io/)
* [deSEC.io DNS API documentation](https://desec.readthedocs.io/)
* [deSEC.io stack](https://github.com/desec-io/desec-stack)
* [list of tools that use the deSEC.io API](https://talk.desec.io/t/tools-implementing-desec)
