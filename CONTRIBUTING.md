How to contribute
=================

Thank you for reading this and for considering to contribute to this project!
This guide gives some hints on how to make the process as smooth and enjoyable
as possible for everyone involved. Please try to follow them, but don't worry
about them too much if anything is unclear or seems daunting. In case of doubt
apply a healthy dose of common sense.

Issues
------

Found a bug? Noticed changes in the [deSEC DNS API](https://desec.readthedocs.io/en/latest/index.html)
or the DNS world that this projects does not yet support? Had an idea for a
quality-of-life feature? Please [open an issue](https://github.com/s-hamann/desec-dns/issues/new/choose).

However, before reporting a bug, please check that you are using the latest
version. If you are not, see if updating fixes the problem.

Submitting changes
------------------

If you want to send some code or documentation changes, please submit them as a
[pull request](https://github.com/s-hamann/desec-dns/pull/new).
Please follow the coding conventions (below) and make sure all of your commits
are atomic (one cleanly separable change per commit).
Similarly, pull requests should only contain isolated changes for a single bug
fix or feature implementation. Do not refactor or reformat code that is
unrelated to the change.

Before making large or complex changes, please open an issue to discuss the
best approach to the problem.

Coding conventions
------------------

To keep the code consistent and readable, we use the following conventions:

* Adhere to [PEP-8](https://peps.python.org/pep-0008/), with a line length limit of 99 characters.
* Format the code using `ruff format` (or `black`).
* Use [Google-style](https://google.github.io/styleguide/pyguide.html#s3.8-comments-and-docstrings) docstrings.
* Use [PEP-484](https://peps.python.org/pep-0484/) type annotations.

License
-------

By contributing to this project, you agree that your contribution will be
licensed under the license specified in the LICENSE file.
