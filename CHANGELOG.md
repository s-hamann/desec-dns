# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The public API in the sense of Semantic Versioning currently consists of the
documented, public classes and functions in the `desec` Python module, with the
exception of those that are marked as not yet stable in the documentation.
The command line interface is not currently considered stable and may change on
minor version bumps. If this happens, it will be clearly marked as a breaking
change in this change log.
Similarly, the project's dependencies are not part of the public API and may
change on minor version bumps. This, too, will be noted as a breaking change in
this file.

## [1.1.0] - 2024-08-24

### Breaking Changes
* Fix domain positional argument being eaten by previous arguments.
  This changes they way multiple values are passed, e.g. multiple records for a
  new record set. The respective option needs to be repeated now, e.g.
  ```sh
  desec add-record -t A -s www -r 192.0.2.1 -r 192.0.2.2 example.com
  ```

### New Features
* Support setting and modifying the `allowed_subnets` token attribute

### Fixes
* Fix incorrect API attribute name in docs

## [1.0.0] - 2024-06-30

* First versioned release

[1.1.0]: https://github.com/s-hamann/desec-dns/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/s-hamann/desec-dns/releases/tag/v1.0.0
