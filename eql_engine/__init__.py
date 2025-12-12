"""
Event Query Language Engine Package.

A lightweight EQL parser and execution engine for querying security events.
"""

from .engine import ExecutionEngine
from .models import (
    ExecutionResult,
    FieldPredicate,
    FilterQuery,
    Match,
    SequenceQuery,
    ThresholdQuery,
    TimeRange,
)
from .parser import parse_query

__all__ = [
    'ExecutionEngine',
    'ExecutionResult',
    'FieldPredicate',
    'FilterQuery',
    'Match',
    'SequenceQuery',
    'ThresholdQuery',
    'TimeRange',
    'parse_query',
]
