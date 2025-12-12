"""
Data models for the Event Query Language engine.

Defines dataclasses for field predicates, query types, timerange metadata,
and match results with full type hints and docstrings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union


@dataclass
class FieldPredicate:
    """Represents a single field comparison predicate.
    
    Attributes:
        field_name: The field name (e.g., 'process.name', 'event.code')
        operator: The comparison operator (==, !=, >, <, >=, <=)
        value: The value to compare against (string, int, or compiled regex)
        is_regex: Whether the value is a compiled regex pattern
    """
    field_name: str
    operator: str
    value: Any
    is_regex: bool = False


@dataclass
class TimeRange:
    """Represents a timerange constraint for a query.
    
    Attributes:
        value: The numeric duration value
        unit: The time unit (s/m/h for seconds/minutes/hours)
    """
    value: int
    unit: str  # 's', 'm', 'h'
    
    def to_timedelta(self) -> timedelta:
        """Convert timerange to a timedelta object."""
        multipliers = {'s': 1, 'm': 60, 'h': 3600}
        seconds = self.value * multipliers.get(self.unit, 1)
        return timedelta(seconds=seconds)


@dataclass
class FilterQuery:
    """Represents a filter query.
    
    Attributes:
        predicates: List of field predicates combined with AND logic
        by_fields: Optional list of fields to group results by
    """
    predicates: List[FieldPredicate]
    by_fields: Optional[List[str]] = None


@dataclass
class SequenceQuery:
    """Represents a sequence query.
    
    Attributes:
        filters: List of filter queries in sequence order
        timerange: Optional timerange constraint for the sequence
        by_fields: Optional list of fields to group results by
    """
    filters: List[FilterQuery]
    timerange: Optional[TimeRange] = None
    by_fields: Optional[List[str]] = None


@dataclass
class ThresholdQuery:
    """Represents a threshold query.
    
    Attributes:
        filter: The filter criteria to match
        min_count: Minimum number of matches required
        timerange: Optional timerange constraint
        by_fields: Optional list of fields to group results by
    """
    filter: FilterQuery
    min_count: int
    timerange: Optional[TimeRange] = None
    by_fields: Optional[List[str]] = None


QueryType = Union[FilterQuery, SequenceQuery, ThresholdQuery]


@dataclass
class Match:
    """Represents a matched event or sequence of events.
    
    Attributes:
        events: List of matched event dictionaries
        timestamp: The earliest timestamp in the match
        group_key: Optional grouping key for grouped results
    """
    events: List[Dict[str, Any]]
    timestamp: datetime
    group_key: Optional[str] = None
    
    def __lt__(self, other: 'Match') -> bool:
        """Allow sorting matches by timestamp."""
        return self.timestamp < other.timestamp


@dataclass
class ExecutionResult:
    """Result of executing a query against events.
    
    Attributes:
        matches: List of matched results
        total_matches: Total number of matches found
        total_events_processed: Total events examined
        execution_time_ms: Execution time in milliseconds
        errors: List of any errors encountered during execution
    """
    matches: List[Match]
    total_matches: int
    total_events_processed: int
    execution_time_ms: float
    errors: List[str] = field(default_factory=list)
