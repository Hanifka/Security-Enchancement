"""
Unit tests for the EQL Engine.

Tests parsing, regex handling, timerange boundaries, validation errors,
and the CLI batch workflow.
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from eql_engine import (
    ExecutionEngine,
    ExecutionResult,
    FieldPredicate,
    FilterQuery,
    Match,
    SequenceQuery,
    ThresholdQuery,
    TimeRange,
    parse_query,
)


class TestTokenizerAndParser:
    """Test cases for the tokenizer and parser."""
    
    def test_parse_simple_filter(self):
        """Test parsing a simple filter query."""
        query_str = 'filter(process.name == "cmd.exe")'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, FilterQuery)
        assert len(query.predicates) == 1
        assert query.predicates[0].field_name == "process.name"
        assert query.predicates[0].operator == "=="
        assert query.predicates[0].value == "cmd.exe"
        assert timerange is None
    
    def test_parse_filter_with_multiple_predicates(self):
        """Test parsing a filter with multiple AND predicates."""
        query_str = 'filter(process.name == "cmd.exe" and process.pid > 100)'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, FilterQuery)
        assert len(query.predicates) == 2
        assert query.predicates[0].field_name == "process.name"
        assert query.predicates[1].field_name == "process.pid"
        assert query.predicates[1].value == 100
    
    def test_parse_filter_with_regex(self):
        """Test parsing a filter with regex literal."""
        query_str = r'filter(process.name == /cmd.*\.exe/)'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, FilterQuery)
        assert query.predicates[0].is_regex
        assert query.predicates[0].value.pattern == "cmd.*\\.exe"
    
    def test_parse_filter_with_timerange(self):
        """Test parsing a filter with timerange."""
        query_str = 'filter(process.name == "cmd.exe") | timerange 5m'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, FilterQuery)
        assert timerange is not None
        assert timerange.value == 5
        assert timerange.unit == 'm'
    
    def test_parse_filter_with_by_clause(self):
        """Test parsing a filter with by clause."""
        query_str = 'filter(event.code == 4688) by process.pid'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, FilterQuery)
        assert query.by_fields == ["process.pid"]
    
    def test_parse_filter_with_multiple_by_fields(self):
        """Test parsing a filter with multiple by fields."""
        query_str = 'filter(event.code == 4688) by process.pid, host.name'
        query, timerange = parse_query(query_str)
        
        assert query.by_fields == ["process.pid", "host.name"]
    
    def test_parse_sequence(self):
        """Test parsing a sequence query."""
        query_str = (
            'sequence['
            'filter(event.code == 4688), '
            'filter(process.name == "cmd.exe")'
            ']'
        )
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, SequenceQuery)
        assert len(query.filters) == 2
        assert len(query.filters[0].predicates) == 1
        assert len(query.filters[1].predicates) == 1
    
    def test_parse_sequence_with_timerange(self):
        """Test parsing a sequence with timerange."""
        query_str = (
            'sequence['
            'filter(event.code == 4688), '
            'filter(process.name == "cmd.exe")'
            '] | timerange 30s'
        )
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, SequenceQuery)
        assert query.timerange is not None
        assert query.timerange.value == 30
        assert query.timerange.unit == 's'
    
    def test_parse_threshold(self):
        """Test parsing a threshold query."""
        query_str = 'threshold(filter(event.code == 4625), min_count = 10)'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, ThresholdQuery)
        assert query.min_count == 10
        assert isinstance(query.filter, FilterQuery)
    
    def test_parse_threshold_with_timerange(self):
        """Test parsing a threshold with timerange."""
        query_str = 'threshold(filter(event.code == 4625), min_count = 5) | timerange 1h'
        query, timerange = parse_query(query_str)
        
        assert isinstance(query, ThresholdQuery)
        assert query.timerange.value == 1
        assert query.timerange.unit == 'h'
    
    def test_parse_all_operators(self):
        """Test parsing all comparison operators."""
        operators = [
            ('==', 'EQ'),
            ('!=', 'NEQ'),
            ('>', 'GT'),
            ('<', 'LT'),
            ('>=', 'GTE'),
            ('<=', 'LTE'),
        ]
        
        for op_str, op_type in operators:
            query_str = f'filter(field.name {op_str} "value")'
            query, _ = parse_query(query_str)
            
            assert query.predicates[0].operator == op_str
    
    def test_parse_numeric_value(self):
        """Test parsing numeric values."""
        query_str = 'filter(process.pid == 1234)'
        query, _ = parse_query(query_str)
        
        assert isinstance(query.predicates[0].value, int)
        assert query.predicates[0].value == 1234
    
    def test_parse_colon_alias_syntax(self):
        """Test parsing colon alias syntax."""
        query_str = 'filter(field: alias == "value")'
        query, _ = parse_query(query_str)
        
        # The alias is used as the field name
        assert query.predicates[0].field_name == "alias"
    
    def test_parse_error_empty_query(self):
        """Test error on empty query."""
        with pytest.raises(SyntaxError):
            parse_query("")
    
    def test_parse_error_invalid_operator(self):
        """Test error on invalid operator."""
        with pytest.raises(SyntaxError):
            parse_query('filter(field.name @ "value")')
    
    def test_parse_error_invalid_regex(self):
        """Test error on invalid regex."""
        with pytest.raises(SyntaxError):
            parse_query('filter(field.name == /[invalid(regex/)')


class TestExecutionEngine:
    """Test cases for the execution engine."""
    
    def test_execute_simple_filter(self):
        """Test executing a simple filter."""
        query_str = 'filter(event_code == 4688)'
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4688, "timestamp": datetime.now()},
            {"event_code": 4689, "timestamp": datetime.now()},
            {"event_code": 4688, "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 2
        assert result.total_events_processed == 3
        assert len(result.matches) == 2
    
    def test_execute_filter_with_nested_fields(self):
        """Test executing a filter with dotted field paths."""
        query_str = 'filter(process.name == "cmd.exe")'
        query, timerange = parse_query(query_str)
        
        events = [
            {
                "process": {"name": "cmd.exe", "pid": 100},
                "timestamp": datetime.now(),
            },
            {
                "process": {"name": "powershell.exe", "pid": 200},
                "timestamp": datetime.now(),
            },
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 1
        assert result.matches[0].events[0]["process"]["name"] == "cmd.exe"
    
    def test_execute_filter_with_regex(self):
        """Test executing a filter with regex matching."""
        query_str = r'filter(process.name == /cmd.*\.exe/)'
        query, timerange = parse_query(query_str)
        
        events = [
            {"process": {"name": "cmd.exe"}, "timestamp": datetime.now()},
            {"process": {"name": "cmdline.exe"}, "timestamp": datetime.now()},
            {"process": {"name": "powershell.exe"}, "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 2
    
    def test_execute_filter_with_numeric_comparison(self):
        """Test executing a filter with numeric comparisons."""
        query_str = 'filter(event_code > 4680 and event_code < 4690)'
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4679, "timestamp": datetime.now()},
            {"event_code": 4685, "timestamp": datetime.now()},
            {"event_code": 4690, "timestamp": datetime.now()},
            {"event_code": 4688, "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 2
    
    def test_execute_sequence(self):
        """Test executing a sequence query."""
        query_str = (
            'sequence['
            'filter(event_type == "login"), '
            'filter(event_type == "command")'
            ']'
        )
        query, timerange = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"event_type": "login", "user": "admin", "timestamp": base_time},
            {"event_type": "command", "user": "admin", "timestamp": base_time + timedelta(seconds=5)},
            {"event_type": "login", "user": "user1", "timestamp": base_time + timedelta(seconds=10)},
            {"event_type": "command", "user": "user1", "timestamp": base_time + timedelta(seconds=15)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        # Should find 3 sequences (without by clause, it finds all valid sequences)
        # admin login -> admin command, admin login -> user1 command, user1 login -> user1 command
        assert result.total_matches == 3
    
    def test_execute_sequence_with_timerange(self):
        """Test executing a sequence with timerange constraint."""
        query_str = (
            'sequence['
            'filter(event_type == "login"), '
            'filter(event_type == "command")'
            '] | timerange 10s'
        )
        query, timerange = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"event_type": "login", "user": "admin", "timestamp": base_time},
            {"event_type": "command", "user": "admin", "timestamp": base_time + timedelta(seconds=5)},
            {"event_type": "command", "user": "admin", "timestamp": base_time + timedelta(seconds=20)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        # Only the login->command within 10s should match
        assert result.total_matches == 1
    
    def test_execute_threshold(self):
        """Test executing a threshold query."""
        query_str = 'threshold(filter(event_code == 4625), min_count = 3)'
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4625, "user": "user1", "timestamp": datetime.now()},
            {"event_code": 4625, "user": "user1", "timestamp": datetime.now()},
            {"event_code": 4625, "user": "user1", "timestamp": datetime.now()},
            {"event_code": 4624, "user": "user1", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 1
        assert len(result.matches[0].events) == 3
    
    def test_execute_threshold_with_by_clause(self):
        """Test executing a threshold with grouping."""
        query_str = (
            'threshold(filter(event_code == 4625), min_count = 2) by user'
        )
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4625, "user": "user1", "timestamp": datetime.now()},
            {"event_code": 4625, "user": "user1", "timestamp": datetime.now()},
            {"event_code": 4625, "user": "user2", "timestamp": datetime.now()},
            {"event_code": 4624, "user": "user2", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        # Only user1 has >= 2 matches
        assert result.total_matches == 1
    
    def test_execute_threshold_insufficient_count(self):
        """Test threshold returns no matches when count is insufficient."""
        query_str = 'threshold(filter(event_code == 4625), min_count = 5)'
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4625, "timestamp": datetime.now()},
            {"event_code": 4625, "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 0
    
    def test_execute_filter_with_by_clause(self):
        """Test filter execution with grouping."""
        query_str = 'filter(event_code == 4688) by user'
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4688, "user": "admin", "timestamp": datetime.now()},
            {"event_code": 4688, "user": "admin", "timestamp": datetime.now()},
            {"event_code": 4688, "user": "user1", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        # Should have one match per group (not per event)
        assert result.total_matches == 2
        # Should have one match for admin with 2 events
        admin_matches = [m for m in result.matches if m.group_key == "admin"]
        assert len(admin_matches) == 1
        assert len(admin_matches[0].events) == 2
        # Should have one match for user1 with 1 event
        user1_matches = [m for m in result.matches if m.group_key == "user1"]
        assert len(user1_matches) == 1
        assert len(user1_matches[0].events) == 1
    
    def test_execute_missing_field(self):
        """Test that missing fields return no match."""
        query_str = 'filter(nonexistent.field == "value")'
        query, timerange = parse_query(query_str)
        
        events = [
            {"other_field": "value", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        assert result.total_matches == 0
    
    def test_timerange_to_timedelta(self):
        """Test timerange conversion to timedelta."""
        timerange_s = TimeRange(value=30, unit='s')
        assert timerange_s.to_timedelta() == timedelta(seconds=30)
        
        timerange_m = TimeRange(value=5, unit='m')
        assert timerange_m.to_timedelta() == timedelta(minutes=5)
        
        timerange_h = TimeRange(value=2, unit='h')
        assert timerange_h.to_timedelta() == timedelta(hours=2)
    
    def test_execute_with_missing_timestamp(self):
        """Test execution with events missing timestamp field."""
        query_str = 'filter(event_code == 4688)'
        query, timerange = parse_query(query_str)
        
        events = [
            {"event_code": 4688},  # No timestamp
            {"event_code": 4688, "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        # Should still match both events
        assert result.total_matches == 2
    
    def test_event_sorting_by_timestamp(self):
        """Test that events are sorted by timestamp."""
        query_str = 'filter(event_code == 4688)'
        query, timerange = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"event_code": 4688, "id": 3, "timestamp": base_time + timedelta(seconds=20)},
            {"event_code": 4688, "id": 1, "timestamp": base_time},
            {"event_code": 4688, "id": 2, "timestamp": base_time + timedelta(seconds=10)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events, timerange)
        
        # Results should be sorted by timestamp
        assert result.matches[0].events[0]["id"] == 1
        assert result.matches[1].events[0]["id"] == 2
        assert result.matches[2].events[0]["id"] == 3


class TestRegexHandling:
    """Test cases for regex pattern handling."""
    
    def test_regex_exact_match(self):
        """Test regex exact matching."""
        query_str = r'filter(command == /powershell\.exe/)'
        query, _ = parse_query(query_str)
        
        events = [
            {"command": "powershell.exe", "timestamp": datetime.now()},
            {"command": "powershell", "timestamp": datetime.now()},
            {"command": "c:\\windows\\powershell.exe", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        # Only the exact match should be found
        assert result.total_matches == 1
    
    def test_regex_case_sensitive(self):
        """Test that regex is case-sensitive."""
        query_str = r'filter(name == /CMD\.exe/)'
        query, _ = parse_query(query_str)
        
        events = [
            {"name": "cmd.exe", "timestamp": datetime.now()},
            {"name": "CMD.exe", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        assert result.total_matches == 1
        assert result.matches[0].events[0]["name"] == "CMD.exe"
    
    def test_regex_negation(self):
        """Test regex negation with !=."""
        query_str = 'filter(name != /cmd.*/)'
        query, _ = parse_query(query_str)
        
        events = [
            {"name": "cmd.exe", "timestamp": datetime.now()},
            {"name": "cmdline.exe", "timestamp": datetime.now()},
            {"name": "powershell.exe", "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        assert result.total_matches == 1
        assert result.matches[0].events[0]["name"] == "powershell.exe"


class TestTimerangeBoundaries:
    """Test cases for timerange boundary conditions."""
    
    def test_timerange_exact_boundary(self):
        """Test timerange at exact boundary."""
        query_str = 'sequence[filter(type == "A"), filter(type == "B")] | timerange 10s'
        query, _ = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"type": "A", "timestamp": base_time},
            {"type": "B", "timestamp": base_time + timedelta(seconds=10)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        # Should be within the boundary
        assert result.total_matches == 1
    
    def test_timerange_exceeded(self):
        """Test timerange exceeding boundary."""
        query_str = 'sequence[filter(type == "A"), filter(type == "B")] | timerange 5s'
        query, _ = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"type": "A", "timestamp": base_time},
            {"type": "B", "timestamp": base_time + timedelta(seconds=10)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        # Should not match due to timerange
        assert result.total_matches == 0
    
    def test_threshold_with_timerange(self):
        """Test threshold respecting timerange window."""
        query_str = 'threshold(filter(type == "error"), min_count = 2) | timerange 5s'
        query, _ = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"type": "error", "timestamp": base_time},
            {"type": "error", "timestamp": base_time + timedelta(seconds=3)},
            {"type": "error", "timestamp": base_time + timedelta(seconds=10)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        # First two errors are within 5s window
        assert result.total_matches == 1


class TestCLIFunctionality:
    """Test cases for CLI functionality."""
    
    def test_load_events_ndjson(self):
        """Test loading NDJSON format events."""
        from run_rules import load_events
        
        ndjson_content = (
            '{"event_code": 4688, "user": "admin"}\n'
            '{"event_code": 4689, "user": "user1"}\n'
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ndjson', delete=False) as f:
            f.write(ndjson_content)
            f.flush()
            temp_file = f.name
        
        try:
            events = load_events(temp_file)
            assert len(events) == 2
            assert events[0]["event_code"] == 4688
            assert events[1]["event_code"] == 4689
        finally:
            Path(temp_file).unlink()
    
    def test_load_events_json_array(self):
        """Test loading JSON array format events."""
        from run_rules import load_events
        
        json_content = json.dumps([
            {"event_code": 4688, "user": "admin"},
            {"event_code": 4689, "user": "user1"},
        ])
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json_content)
            f.flush()
            temp_file = f.name
        
        try:
            events = load_events(temp_file)
            assert len(events) == 2
            assert events[0]["event_code"] == 4688
        finally:
            Path(temp_file).unlink()
    
    def test_load_rules_json(self):
        """Test loading rules from JSON file."""
        from run_rules import load_rules
        
        rules = {
            "brute_force": 'threshold(filter(event_code == 4625), min_count = 5)',
            "process_creation": 'filter(event_code == 4688)',
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules, f)
            f.flush()
            temp_file = f.name
        
        try:
            loaded_rules = load_rules(temp_file)
            assert len(loaded_rules) == 2
            assert "brute_force" in loaded_rules
            assert "process_creation" in loaded_rules
        finally:
            Path(temp_file).unlink()
    
    def test_cli_batch_execution(self):
        """Test CLI batch rule execution via internal API."""
        # Test batch execution at a lower level without CLI side effects
        rules = {
            "rule1": 'filter(code == 1)',
            "rule2": 'filter(code == 2)',
        }
        
        events = [
            {"code": 1, "timestamp": datetime.now()},
            {"code": 2, "timestamp": datetime.now()},
        ]
        
        # Test each rule directly
        engine = ExecutionEngine()
        
        for rule_name, query_str in rules.items():
            parsed_query, timerange = parse_query(query_str)
            result = engine.execute(parsed_query, events, timerange)
            
            if rule_name == "rule1":
                assert result.total_matches == 1
            elif rule_name == "rule2":
                assert result.total_matches == 1


class TestValidationErrors:
    """Test cases for validation error handling."""
    
    def test_invalid_syntax_missing_paren(self):
        """Test error on missing parenthesis."""
        with pytest.raises(SyntaxError):
            parse_query('filter(event_code == 4688')
    
    def test_invalid_syntax_unknown_token(self):
        """Test error on unknown token."""
        with pytest.raises(SyntaxError):
            parse_query('filter(event_code @ 4688)')
    
    def test_invalid_timerange_unit(self):
        """Test error on invalid timerange unit."""
        with pytest.raises(SyntaxError):
            parse_query('filter(code == 1) | timerange 5x')
    
    def test_invalid_threshold_missing_min_count(self):
        """Test error on missing min_count in threshold."""
        with pytest.raises(SyntaxError):
            parse_query('threshold(filter(code == 1), value = 5)')
    
    def test_execution_result_timestamps_sorted(self):
        """Test that execution results are sorted by timestamp."""
        query_str = 'filter(code == 1)'
        query, _ = parse_query(query_str)
        
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            {"code": 1, "id": 3, "timestamp": base_time + timedelta(seconds=30)},
            {"code": 1, "id": 1, "timestamp": base_time},
            {"code": 1, "id": 2, "timestamp": base_time + timedelta(seconds=10)},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        # Matches should be sorted by timestamp
        assert result.matches[0].timestamp < result.matches[1].timestamp
        assert result.matches[1].timestamp < result.matches[2].timestamp
    
    def test_execution_result_stats(self):
        """Test that execution result statistics are correct."""
        query_str = 'filter(code == 1)'
        query, _ = parse_query(query_str)
        
        events = [
            {"code": 1, "timestamp": datetime.now()},
            {"code": 2, "timestamp": datetime.now()},
            {"code": 1, "timestamp": datetime.now()},
        ]
        
        engine = ExecutionEngine()
        result = engine.execute(query, events)
        
        assert result.total_matches == 2
        assert result.total_events_processed == 3
        assert result.execution_time_ms > 0
        assert len(result.errors) == 0
