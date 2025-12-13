"""
EQL query execution engine.

Implements batch execution utilities for sorting events by timestamp,
normalizing dotted field paths, evaluating predicates, enforcing timerange
windows, and returning ordered match sets plus summary statistics.
"""

import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    ExecutionResult,
    FieldPredicate,
    FilterQuery,
    Match,
    SequenceQuery,
    ThresholdQuery,
    TimeRange,
)


class ExecutionEngine:
    """Executes EQL queries against event data."""
    
    def __init__(self):
        """Initialize the execution engine."""
        pass
    
    def execute(
        self,
        query: FilterQuery | SequenceQuery | ThresholdQuery,
        events: List[Dict[str, Any]],
        timerange: Optional[TimeRange] = None,
    ) -> ExecutionResult:
        """Execute a query against a list of events.
        
        Args:
            query: The query to execute
            events: List of event dictionaries
            timerange: Optional additional timerange constraint
            
        Returns:
            ExecutionResult with matches and statistics
        """
        start_time = time.time()
        errors = []
        
        try:
            # Normalize and sort events by timestamp
            normalized_events = self._normalize_events(events, errors)
            sorted_events = self._sort_events_by_timestamp(normalized_events)
            
            # Execute appropriate query type
            if isinstance(query, FilterQuery):
                matches = self._execute_filter(query, sorted_events, timerange)
            elif isinstance(query, SequenceQuery):
                matches = self._execute_sequence(query, sorted_events)
            elif isinstance(query, ThresholdQuery):
                matches = self._execute_threshold(query, sorted_events, timerange)
            else:
                raise ValueError(f"Unknown query type: {type(query)}")
            
            # Sort matches by timestamp
            matches.sort()
            
        except Exception as e:
            matches = []
            errors.append(str(e))
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return ExecutionResult(
            matches=matches,
            total_matches=len(matches),
            total_events_processed=len(events),
            execution_time_ms=elapsed_ms,
            errors=errors,
        )
    
    def _normalize_events(
        self,
        events: List[Dict[str, Any]],
        errors: List[str],
    ) -> List[Dict[str, Any]]:
        """Normalize events, extracting and standardizing timestamps.
        
        Args:
            events: Raw event dictionaries
            errors: List to append normalization errors to
            
        Returns:
            List of normalized events with standardized timestamps
        """
        normalized = []
        
        for event in events:
            normalized_event = dict(event)
            
            # Try to extract timestamp if not present
            if 'timestamp' not in normalized_event:
                timestamp = self._extract_timestamp(event)
                if timestamp:
                    normalized_event['timestamp'] = timestamp
                else:
                    # Use current time as fallback
                    normalized_event['timestamp'] = datetime.now()
            elif isinstance(normalized_event['timestamp'], str):
                try:
                    # Try to parse ISO format
                    normalized_event['timestamp'] = datetime.fromisoformat(
                        normalized_event['timestamp'].replace('Z', '+00:00')
                    )
                except (ValueError, AttributeError):
                    # Fallback to current time
                    normalized_event['timestamp'] = datetime.now()
            
            normalized.append(normalized_event)
        
        return normalized
    
    def _extract_timestamp(self, event: Dict[str, Any]) -> Optional[datetime]:
        """Try to extract timestamp from event using common field names.
        
        Args:
            event: Event dictionary
            
        Returns:
            Extracted datetime or None
        """
        timestamp_fields = [
            '@timestamp', 'ts', 'time', 'datetime',
            'event_time', 'created_at', 'date',
        ]
        
        for field in timestamp_fields:
            if field in event:
                value = event[field]
                if isinstance(value, datetime):
                    return value
                elif isinstance(value, (int, float)):
                    try:
                        return datetime.fromtimestamp(value)
                    except (ValueError, OSError):
                        pass
                elif isinstance(value, str):
                    try:
                        return datetime.fromisoformat(
                            value.replace('Z', '+00:00')
                        )
                    except ValueError:
                        pass
        
        return None
    
    def _sort_events_by_timestamp(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Sort events by timestamp in ascending order.
        
        Args:
            events: Events to sort
            
        Returns:
            Sorted events
        """
        return sorted(
            events,
            key=lambda e: e.get('timestamp', datetime.min)
        )
    
    def _get_field_value(
        self,
        event: Dict[str, Any],
        field_path: str,
    ) -> Optional[Any]:
        """Get a field value from an event, supporting dotted field paths.
        
        Args:
            event: Event dictionary
            field_path: Field path (e.g., 'process.name', 'agent.id')
            
        Returns:
            Field value or None if not found
        """
        parts = field_path.split('.')
        current = event
        
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
                if current is None:
                    return None
            else:
                return None
        
        return current
    
    def _evaluate_predicate(
        self,
        event: Dict[str, Any],
        predicate: FieldPredicate,
    ) -> bool:
        """Evaluate a single predicate against an event.
        
        Args:
            event: Event to evaluate
            predicate: Predicate to evaluate
            
        Returns:
            True if predicate matches, False otherwise
        """
        value = self._get_field_value(event, predicate.field_name)
        
        if value is None:
            return False
        
        if predicate.is_regex:
            # Regex matching
            str_value = str(value)
            if predicate.operator == '==':
                return predicate.value.match(str_value) is not None
            elif predicate.operator == '!=':
                return predicate.value.match(str_value) is None
            else:
                return False
        else:
            # Numeric/string comparison
            try:
                # Try numeric comparison if both are numeric
                if isinstance(value, (int, float)) and isinstance(predicate.value, (int, float)):
                    num_value = float(value)
                    num_compare = float(predicate.value)
                    
                    if predicate.operator == '==':
                        return num_value == num_compare
                    elif predicate.operator == '!=':
                        return num_value != num_compare
                    elif predicate.operator == '>':
                        return num_value > num_compare
                    elif predicate.operator == '<':
                        return num_value < num_compare
                    elif predicate.operator == '>=':
                        return num_value >= num_compare
                    elif predicate.operator == '<=':
                        return num_value <= num_compare
            except (ValueError, TypeError):
                pass
            
            # String comparison
            str_value = str(value)
            str_compare = str(predicate.value)
            
            if predicate.operator == '==':
                return str_value == str_compare
            elif predicate.operator == '!=':
                return str_value != str_compare
            elif predicate.operator == '>':
                return str_value > str_compare
            elif predicate.operator == '<':
                return str_value < str_compare
            elif predicate.operator == '>=':
                return str_value >= str_compare
            elif predicate.operator == '<=':
                return str_value <= str_compare
        
        return False
    
    def _evaluate_filter(
        self,
        event: Dict[str, Any],
        filter_query: FilterQuery,
    ) -> bool:
        """Evaluate all predicates in a filter (AND logic).
        
        Args:
            event: Event to evaluate
            filter_query: Filter to evaluate
            
        Returns:
            True if all predicates match
        """
        for predicate in filter_query.predicates:
            if not self._evaluate_predicate(event, predicate):
                return False
        return True
    
    def _execute_filter(
        self,
        query: FilterQuery,
        events: List[Dict[str, Any]],
        timerange: Optional[TimeRange] = None,
    ) -> List[Match]:
        """Execute a filter query.
        
        Args:
            query: Filter query to execute
            events: Events to filter
            timerange: Optional timerange constraint
            
        Returns:
            List of matches
        """
        matches = []
        
        if query.by_fields:
            # Group by specified fields
            groups: Dict[str, List[Dict[str, Any]]] = {}
            
            for event in events:
                group_key = self._build_group_key(event, query.by_fields)
                if group_key not in groups:
                    groups[group_key] = []
                groups[group_key].append(event)
            
            for group_key, group_events in groups.items():
                matching_events = [
                    e for e in group_events
                    if self._evaluate_filter(e, query)
                ]
                
                if matching_events:
                    # Apply timerange
                    if timerange:
                        matching_events = self._apply_timerange(
                            matching_events, timerange
                        )
                    
                    if matching_events:
                        match = Match(
                            events=matching_events,
                            timestamp=matching_events[0].get('timestamp', datetime.now()),
                            group_key=group_key,
                        )
                        matches.append(match)
        else:
            # No grouping
            matching_events = [
                e for e in events
                if self._evaluate_filter(e, query)
            ]
            
            if matching_events:
                # Apply timerange
                if timerange:
                    matching_events = self._apply_timerange(
                        matching_events, timerange
                    )
                
                if matching_events:
                    for event in matching_events:
                        match = Match(
                            events=[event],
                            timestamp=event.get('timestamp', datetime.now()),
                        )
                        matches.append(match)
        
        return matches
    
    def _execute_sequence(
        self,
        query: SequenceQuery,
        events: List[Dict[str, Any]],
    ) -> List[Match]:
        """Execute a sequence query.
        
        Args:
            query: Sequence query to execute
            events: Events to search
            
        Returns:
            List of matches
        """
        matches = []
        
        if not query.filters:
            return matches
        
        if query.by_fields:
            # Group by specified fields
            groups: Dict[str, List[Dict[str, Any]]] = {}
            
            for event in events:
                group_key = self._build_group_key(event, query.by_fields)
                if group_key not in groups:
                    groups[group_key] = []
                groups[group_key].append(event)
            
            for group_key, group_events in groups.items():
                group_matches = self._find_sequences(
                    query.filters, group_events, query.timerange
                )
                for match in group_matches:
                    match.group_key = group_key
                    matches.append(match)
        else:
            # No grouping
            matches = self._find_sequences(
                query.filters, events, query.timerange
            )
        
        return matches
    
    def _find_sequences(
        self,
        filters: List[FilterQuery],
        events: List[Dict[str, Any]],
        timerange: Optional[TimeRange] = None,
    ) -> List[Match]:
        """Find sequences of events matching the filters in order.
        
        Args:
            filters: Sequence of filters to match in order
            events: Events to search
            timerange: Optional timerange constraint
            
        Returns:
            List of matching sequences
        """
        matches = []
        
        if not filters or not events:
            return matches
        
        # Find all events matching the first filter
        first_matches = [
            (i, e) for i, e in enumerate(events)
            if self._evaluate_filter(e, filters[0])
        ]
        
        if len(filters) == 1:
            # Only one filter - return each match
            for idx, event in first_matches:
                if timerange is None or self._check_timerange([event], timerange):
                    match = Match(
                        events=[event],
                        timestamp=event.get('timestamp', datetime.now()),
                    )
                    matches.append(match)
        else:
            # Multiple filters - find sequences
            for start_idx, first_event in first_matches:
                sequence = self._find_sequence_from(
                    filters[1:],
                    events,
                    start_idx + 1,
                    [first_event],
                    timerange,
                )
                matches.extend(sequence)
        
        return matches
    
    def _find_sequence_from(
        self,
        remaining_filters: List[FilterQuery],
        events: List[Dict[str, Any]],
        start_idx: int,
        sequence_events: List[Dict[str, Any]],
        timerange: Optional[TimeRange] = None,
    ) -> List[Match]:
        """Recursively find sequence continuations.
        
        Args:
            remaining_filters: Remaining filters to match
            events: All events
            start_idx: Index to start searching from
            sequence_events: Events matched so far in the sequence
            timerange: Optional timerange constraint
            
        Returns:
            List of completed matches
        """
        matches = []
        
        if not remaining_filters:
            # Sequence complete
            if timerange is None or self._check_timerange(sequence_events, timerange):
                match = Match(
                    events=sequence_events,
                    timestamp=sequence_events[0].get('timestamp', datetime.now()),
                )
                matches.append(match)
            return matches
        
        # Find next matching event
        current_filter = remaining_filters[0]
        next_filters = remaining_filters[1:]
        
        for idx in range(start_idx, len(events)):
            event = events[idx]
            
            if self._evaluate_filter(event, current_filter):
                # Found a match, continue sequence
                new_sequence = sequence_events + [event]
                
                if timerange and not self._check_timerange(new_sequence, timerange):
                    # Timerange exceeded, don't continue from this point
                    continue
                
                matches.extend(
                    self._find_sequence_from(
                        next_filters,
                        events,
                        idx + 1,
                        new_sequence,
                        timerange,
                    )
                )
        
        return matches
    
    def _execute_threshold(
        self,
        query: ThresholdQuery,
        events: List[Dict[str, Any]],
        timerange: Optional[TimeRange] = None,
    ) -> List[Match]:
        """Execute a threshold query.
        
        Args:
            query: Threshold query to execute
            events: Events to search
            timerange: Optional timerange constraint (overridden by query.timerange)
            
        Returns:
            List of matches
        """
        matches = []
        
        # Use query timerange if available, otherwise use passed timerange
        effective_timerange = query.timerange or timerange
        
        if query.by_fields:
            # Group by specified fields
            groups: Dict[str, List[Dict[str, Any]]] = {}
            
            for event in events:
                group_key = self._build_group_key(event, query.by_fields)
                if group_key not in groups:
                    groups[group_key] = []
                groups[group_key].append(event)
            
            for group_key, group_events in groups.items():
                matching_events = [
                    e for e in group_events
                    if self._evaluate_filter(e, query.filter)
                ]
                
                if len(matching_events) >= query.min_count:
                    # Apply timerange if specified
                    if effective_timerange:
                        matching_events = self._apply_timerange(
                            matching_events, effective_timerange
                        )
                        
                        # Check count after timerange applied
                        if len(matching_events) < query.min_count:
                            continue
                    
                    match = Match(
                        events=matching_events,
                        timestamp=matching_events[0].get('timestamp', datetime.now()),
                        group_key=group_key,
                    )
                    matches.append(match)
        else:
            # No grouping - check overall count
            matching_events = [
                e for e in events
                if self._evaluate_filter(e, query.filter)
            ]
            
            if len(matching_events) >= query.min_count:
                # Apply timerange if specified
                if effective_timerange:
                    matching_events = self._apply_timerange(
                        matching_events, effective_timerange
                    )
                    
                    # Check count after timerange applied
                    if len(matching_events) < query.min_count:
                        return matches
                
                match = Match(
                    events=matching_events,
                    timestamp=matching_events[0].get('timestamp', datetime.now()),
                )
                matches.append(match)
        
        return matches
    
    def _build_group_key(
        self,
        event: Dict[str, Any],
        by_fields: List[str],
    ) -> str:
        """Build a grouping key from specified fields.
        
        Args:
            event: Event to extract fields from
            by_fields: Field names to use for grouping
            
        Returns:
            Comma-separated group key
        """
        parts = []
        for field in by_fields:
            value = self._get_field_value(event, field)
            parts.append(str(value))
        return ','.join(parts)
    
    def _check_timerange(
        self,
        events: List[Dict[str, Any]],
        timerange: TimeRange,
    ) -> bool:
        """Check if a set of events fits within a timerange window.
        
        Args:
            events: Events to check
            timerange: Timerange constraint
            
        Returns:
            True if all events fit within the window
        """
        if not events:
            return True
        
        timestamps = [
            e.get('timestamp', datetime.now()) for e in events
        ]
        min_time = min(timestamps)
        max_time = max(timestamps)
        
        duration = max_time - min_time
        max_duration = timerange.to_timedelta()
        
        return duration <= max_duration
    
    def _apply_timerange(
        self,
        events: List[Dict[str, Any]],
        timerange: TimeRange,
    ) -> List[Dict[str, Any]]:
        """Filter events to only those within timerange windows.
        
        Args:
            events: Events to filter
            timerange: Timerange constraint
            
        Returns:
            Filtered events
        """
        if not events:
            return events
        
        max_duration = timerange.to_timedelta()
        
        # For each event as a potential window start, find all events
        # within the timerange
        result = []
        
        for i, start_event in enumerate(events):
            start_time = start_event.get('timestamp', datetime.now())
            end_time = start_time + max_duration
            
            window_events = [
                e for e in events
                if start_time <= e.get('timestamp', datetime.now()) <= end_time
            ]
            
            if window_events:
                # Only add if this would create a new sequence
                if not result or window_events[0] != result[-1]:
                    result.extend(window_events)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_result = []
        for event in result:
            event_id = id(event)
            if event_id not in seen:
                seen.add(event_id)
                unique_result.append(event)
        
        return unique_result
