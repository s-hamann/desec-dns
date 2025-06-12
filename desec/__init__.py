"""Simple API client for desec.io.

It consists of a python module and a CLI tool.
For more information on the CLI, run 'desec --help'.
For more information on the module's classes and functions, refer to the respective
docstrings.
"""

from __future__ import annotations

import typing as t

import desec.types

# For backwards compatibility, we import submodule content into the top-level scope.
# To be removed in version 2.0.
from desec.api import *  # noqa: F403
from desec.exceptions import *  # noqa: F403
from desec.tlsa import *  # noqa: F403
from desec.types import *  # noqa: F403
from desec.utils import *  # noqa: F403

__version__ = "0.0.0"


RECORD_TYPES = t.get_args(desec.types.DnsRecordTypeType)
