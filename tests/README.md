About Tests
===========

This directory contains test cases for the deSEC.io API client.

Running Tests
=============

The preferred way to run the tests is using [tox](https://tox.wiki/):

```sh
tox -q run -e py39
```

tox will handle installing the required tools as well as the code to be tested in a virtual environment.

The test suite uses [pytest](https://pytest.org/), which can also be run directly:

```sh
pytest
```

Note that this only works if at least pytest, [pytest-recording](https://github.com/kiwicom/pytest-recording/) and the
code to be tested are installed in the currently active Python environment.

Similar to tox, [Poetry](https://python-poetry.org/) can be used to prepare the required environment and run the tests:

```sh
poetry install --with=dev
poetry run pytest
```

Testing Multiple Python Versions
--------------------------------

tox allows running the test suite on multiple versions of Python.
This only requires the desired Python version and tox to be installed.
tox will handle the rest.

The example above shows how to run the tests with Python 3.9.
To use a different version, simply select another test environment name.
tox can also run the test suite on multiple Python versions, repeating the tests for each version:

```sh
tox -q run -e py39,py310
```

Run `tox list` to get a list of all configured test environments.
Note that not all of them actually run the test suite.

More Control
------------

The following is a short primer on pytest.
Refer to the [documentation](https://docs.pytest.org/en/stable/index.html) for more information.

pytest has a number of options that influence which test cases are selected for running, how the results are
presented, and so on.

When using tox, command line options can be passed to pytest after a `--`, e.g.:

```sh
tox -q run -e py39 -- -v
```

When working on a specific feature or issue, it can be helpful to only run the test cases related to this.
pytest has a number of ways to fine tune test case selection, including but not limited to:
1. Run only tests defined in a specific file:
```sh
tox -q run -e py39 -- tests/test_domain.py
```
2. Run only tests with a specific (test function) name:
```sh
tox -q run -e py39 -- -k list_domains
tox -q run -e py39 -- -k 'domain and not invalid'
```
3. Run only tests that failed in the last run:
```sh
tox -q run -e py39 -- --lf
```

Mocks
=====

As the code mainly interacts with the deSEC.io API, the test suite needs to check that this interaction is correct.
However, it does not do to run all tests on the real API.
Instead, the test suite uses mocks of the HTTP interaction and supplies API responses to the client without actually
querying the API.

This is done mostly transparently using [VCR.py](https://github.com/kevin1024/vcrpy) and
[pytest-recording](https://github.com/kiwicom/pytest-recording/).
VCR.py records and stores real API interactions and later replays the responses.
These recorded interactions are called *cassettes*.

Interaction with the API is therefore only required when adding or substantially changing test cases.
In this case, an authentication token needs to be supplied.
To do so, set the environment variable `DESEC_TOKEN` to the secret value of a token with unlimited permissions for
token and domain management.
Note that the authentication token will not be stored in the cassettes.
However, they may contain other sensitive information from the account, such as domains unrelated to the tests.
It is therefore recommended to carefully review the cassettes before committing them to version control.

Recording New Requests
----------------------

When adding new tests, run pytest with the parameter `--record-mode=once` to add any missing cassettes:

```sh
export DESEC_TOKEN=very-secret-test-token-value
tox -q run -e py39 -- --record-mode=once
```

Existing cassettes will not be changed and actually be used in the respective test cases.

Note that running multiple test cases is likely to hit the [API's rate
limits](https://desec.readthedocs.io/en/latest/rate-limits.html).
Aside from slowing down the tests, this does not have any impact on the cassettes, as throttled interactions are not
recorded (except for test cases that explicitly require this).

Review the new cassettes in `tests/cassettes/...` for any inappropriate content and commit them when satisfied.

Regenerating Cassettes
----------------------

When cassettes are outdated or incorrect, they can be regenerated:

```sh
tox -q run -e py39 -- --record-mode=rewrite
```

This is equivalent to removing them and recoding missing test cases.
It is highly recommended to limit the test case selection to only those cassettes that actually need rewriting.

Ignore Mocks
------------

To completely ignore the mocks and run tests on the live API, run:

```sh
tox -q run -e py39 -- --disable-recording
```

Note that this will neither use existing cassettes nor create any new ones.

Coverage
========

Each test run produces a short overview of the test coverage it achieved.
To combine the results from different test environments into a single data file and show the overall coverage report,
run:

```sh
tox -q run -e coverage
```

It is also possible to generate a HTML report, which provides a detailed visualization of what portions of the code
were tested and which test cases covered them.
After running the following command, the report can be found in the directory `htmlcov`.

```sh
tox -q run -e coverage -- html
```

Similarly, the coverage data can be exported to JSON, XML or LCOV format for further processing:

```sh
tox -q run -e coverage -- json
tox -q run -e coverage -- xml
tox -q run -e coverage -- lcov
```
