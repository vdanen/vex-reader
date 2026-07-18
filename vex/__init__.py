# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from importlib.metadata import PackageNotFoundError, version

from .vex import Vex
from .package import VexPackages
from .simplenvd import NVD
from .simplecve import CVE

try:
    __version__ = version("vex-reader")
except PackageNotFoundError:
    __version__ = "0.0.0"
