#!/usr/bin/env python3
"""
CLI entry point for batch evaluation of EQL queries.

Supports loading NDJSON or JSON array-formatted events and executing
a single query string or iterating over saved rules for batch testing.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from eql_engine import ExecutionEngine, parse_query


def serialize_for_json(obj: Any) -> Any:
    """Recursively serialize objects for JSON output.
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON-serializable version of the object
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_for_json(item) for item in obj]
    else:
        return obj


def load_events(input_file: str) -> List[Dict[str, Any]]:
    """Load events from NDJSON or JSON array file.
    
    Args:
        input_file: Path to input file (NDJSON or JSON)
        
    Returns:
        List of event dictionaries
        
    Raises:
        ValueError: If file format is invalid
    """
    events = []
    path = Path(input_file)
    
    if not path.exists():
        raise ValueError(f"Input file not found: {input_file}")
    
    with open(path, 'r') as f:
        content = f.read().strip()
        
        if not content:
            return events
        
        # Try to detect format
        if content.startswith('['):
            # JSON array format
            try:
                events = json.loads(content)
                if not isinstance(events, list):
                    raise ValueError("JSON must be an array of objects")
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON array: {e}")
        else:
            # NDJSON format
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError(f"Line {line_num}: Event must be a JSON object")
                    events.append(event)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Line {line_num}: Invalid JSON: {e}")
    
    return events


def load_rules(rules_file: str) -> Dict[str, str]:
    """Load rules from a JSON file.
    
    Expected format:
    {
        "rule_name_1": "filter(...)",
        "rule_name_2": "sequence[...]",
        ...
    }
    
    Args:
        rules_file: Path to rules file
        
    Returns:
        Dictionary mapping rule names to query strings
        
    Raises:
        ValueError: If file format is invalid
    """
    rules = {}
    path = Path(rules_file)
    
    if not path.exists():
        raise ValueError(f"Rules file not found: {rules_file}")
    
    with open(path, 'r') as f:
        try:
            content = json.load(f)
            if not isinstance(content, dict):
                raise ValueError("Rules file must contain a JSON object")
            
            for name, query in content.items():
                if not isinstance(query, str):
                    raise ValueError(f"Rule '{name}': Query must be a string")
                rules[name] = query
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in rules file: {e}")
    
    return rules


def execute_single_query(
    query: str,
    events: List[Dict[str, Any]],
    verbose: bool = False,
) -> None:
    """Execute a single query and print results.
    
    Args:
        query: EQL query string
        events: List of events to query
        verbose: Whether to print verbose output
    """
    try:
        # Parse query
        if verbose:
            print(f"Parsing query: {query}", file=sys.stderr)
        
        parsed_query, timerange = parse_query(query)
        
        # Execute query
        if verbose:
            print(f"Executing query against {len(events)} events", file=sys.stderr)
        
        engine = ExecutionEngine()
        result = engine.execute(parsed_query, events, timerange)
        
        # Output results
        output = {
            "total_matches": result.total_matches,
            "total_events_processed": result.total_events_processed,
            "execution_time_ms": result.execution_time_ms,
            "matches": [
                {
                    "events": serialize_for_json(match.events),
                    "timestamp": match.timestamp.isoformat(),
                    "group_key": match.group_key,
                }
                for match in result.matches
            ],
        }
        
        if result.errors:
            output["errors"] = result.errors
        
        print(json.dumps(serialize_for_json(output), indent=2))
        
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2), file=sys.stderr)
        sys.exit(1)


def execute_batch_rules(
    rules_file: str,
    events: List[Dict[str, Any]],
    output_file: str | None = None,
    verbose: bool = False,
) -> None:
    """Execute multiple rules from a file and save results.
    
    Args:
        rules_file: Path to rules file
        events: List of events to query
        output_file: Optional output file path
        verbose: Whether to print verbose output
    """
    try:
        # Load rules
        if verbose:
            print(f"Loading rules from {rules_file}", file=sys.stderr)
        
        rules = load_rules(rules_file)
        
        if not rules:
            print("No rules found in rules file", file=sys.stderr)
            return
        
        engine = ExecutionEngine()
        results = {}
        
        # Execute each rule
        for rule_name, query in rules.items():
            if verbose:
                print(f"Executing rule: {rule_name}", file=sys.stderr)
            
            try:
                parsed_query, timerange = parse_query(query)
                result = engine.execute(parsed_query, events, timerange)
                
                results[rule_name] = {
                    "status": "success",
                    "total_matches": result.total_matches,
                    "total_events_processed": result.total_events_processed,
                    "execution_time_ms": result.execution_time_ms,
                    "matches": [
                        {
                            "events": serialize_for_json(match.events),
                            "timestamp": match.timestamp.isoformat(),
                            "group_key": match.group_key,
                        }
                        for match in result.matches
                    ],
                }
                
                if result.errors:
                    results[rule_name]["errors"] = result.errors
            
            except Exception as e:
                results[rule_name] = {
                    "status": "error",
                    "error": str(e),
                }
        
        # Output results
        output = json.dumps(serialize_for_json(results), indent=2)
        
        if output_file:
            Path(output_file).write_text(output)
            if verbose:
                print(f"Results saved to {output_file}", file=sys.stderr)
        else:
            print(output)
    
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="EQL Engine - Execute queries against event logs"
    )
    
    parser.add_argument(
        "events",
        help="Path to events file (NDJSON or JSON array format)",
    )
    
    parser.add_argument(
        "-q", "--query",
        help="EQL query string to execute",
    )
    
    parser.add_argument(
        "-r", "--rules",
        help="Path to rules file (JSON) for batch execution",
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path for batch results",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    args = parser.parse_args()
    
    # Load events
    try:
        if args.verbose:
            print(f"Loading events from {args.events}", file=sys.stderr)
        
        events = load_events(args.events)
        
        if args.verbose:
            print(f"Loaded {len(events)} events", file=sys.stderr)
    
    except ValueError as e:
        print(f"Error loading events: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Execute appropriate mode
    if args.query:
        execute_single_query(args.query, events, args.verbose)
    elif args.rules:
        execute_batch_rules(args.rules, events, args.output, args.verbose)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
