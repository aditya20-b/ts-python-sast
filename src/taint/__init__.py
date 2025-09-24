"""
Taint analysis and dataflow tracking
"""

from .engine import TaintEngine
from .sources import SourceConfig
from .sinks import SinkConfig

__all__ = ["TaintEngine", "SourceConfig", "SinkConfig"]