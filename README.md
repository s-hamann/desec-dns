deSEC.io API client
===================

[![Code Quality](https://github.com/s-hamann/desec-dns/actions/workflows/code_quality.yml/badge.svg)](https://github.com/s-hamann/desec-dns/actions/workflows/code_quality.yml)
[![codecov](https://codecov.io/gh/s-hamann/desec-dns/graph/badge.svg?token=D9ZE0GXJN0)](https://codecov.io/gh/s-hamann/desec-dns)
[![Documentation](https://github.com/s-hamann/desec-dns/actions/workflows/docs.yml/badge.svg)](https://s-hamann.github.io/desec-dns/)

This is a simple client to manage domains hosted by
[deSEC.io](https://desec.io/) using the deSEC.io API.
It can be used from the command line or as a Python module.

Requirements
============

* Python 3.9+
* [requests](https://github.com/requests/requests)
* [cryptography](https://github.com/pyca/cryptography/) (optional, for high-level
  management of TLSA records)
* [dnspython](https://www.dnspython.org/) (optional, for parsing zone files)

Usage
=====

### CLI

The functionality is split into subcommands, as shown below.
Most subcommand require further parameters to work.
They are described by the usage information of each individual subcommand.

```
usage: desec [-h] [--token TOKEN | --token-file TOKEN_FILE] [--non-blocking] [--blocking] [--debug-http] action ...

A simple deSEC.io API client

positional arguments:
  action
    list-tokens         list all authentication tokens
    create-token        create and return a new authentication token
    modify-token        modify an existing authentication token
    delete-token        delete an authentication token
    list-token-policies
                        list all policies of an authentication token
    add-token-policy    add a policy for an authentication token
    modify-token-policy
                        modify an existing policy for an authentication token
    delete-token-policy
                        delete an existing policy for an authentication token
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
    export-zone         export all records into a zone file
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
  --debug-http          Print details about http requests / responses.
```

### Python Module

This project can also be used as a Python module.
To get started, import the `desec` module and initialize an instance of `APIClient`:

```py
import desec

api_client = desec.APIClient("my-secret-token-value")
```

Refer to the documentation for anything beyond that.
The module's API is documented in standard Python docstrings and type
annotation and can be viewed using any tool that can handle them.
For example, to browse the documentation using [pdoc](https://pdoc.dev/), run:

```sh
pdoc -d google desec
```

The documentation is also [conveniently available online](https://s-hamann.github.io/desec-dns/)
and automatically updated for the `main` branch of this repository.

Installation
============

Currently, the only way to install / use desec-dns is from source.

You can simply run `python desec.py` as-is, as long as the dependencies (see
[above](#requirements)) are installed for your python interpreter.

The package can be installed in a (virtual) environment using 
`pip install -e ./path/to/desc-dns` or 
`pip install git+https://github.com/s-hamann/desec-dns`. That should also make `desec` 
available as a command (if the virtual environment is activated). Note that `desec-dns`
is the **package name**. The **module** is called `desec`, so you need to `import desec`
when using it as a library.

You can use [poetry](https://python-poetry.org/docs/) to manage a virtual environment
with desec installed. That is especially recommended if you want to
[contribute](CONTRIBUTING.md). Run `poetry install --with=dev` to get all dependencies
and necessary tools for formatting, linting, and type-checking. If you want to work on
features that require optional dependencies, `install` the corresponding extras, e.g.:
`poetry install --extras=tlsa` or just go for `poetry install --all-extras`.

Related Work
============

* [deSEC.io - official website](https://desec.io/)
* [deSEC.io DNS API documentation](https://desec.readthedocs.io/)
* [deSEC.io stack](https://github.com/desec-io/desec-stack)
* [list of tools that use the deSEC.io API](https://talk.desec.io/t/tools-implementing-desec)
