# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from importlib.metadata import PackageNotFoundError, version

from .package import VexPackages
from .simplecve import CVE
from .simplenvd import NVD
from .vex import Vex

try:
    __version__ = version("vex-reader")
except PackageNotFoundError:
    __version__ = "0.0.0"
