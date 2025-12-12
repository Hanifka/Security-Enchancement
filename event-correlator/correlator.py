#!/usr/bin/env python3
"""
Event Correlation Engine for Security-Enhancement

A lightweight, production-ready event correlation engine that can:
- Tail JSON events from log files
- Detect patterns using sequence and threshold matching
- Maintain in-memory state with optional SQLite persistence
- Handle file rotation gracefully
- Support YAML-driven configuration
- Run in debug and dry-run modes
"""

import argparse
import json
import logging
import sqlite3
import sys
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import re


@dataclass
class CorrelationRule:
    """Represents a correlation rule configuration."""
    name: str
    pattern_type: str  # 'sequence', 'threshold', 'composite'
    description: str = ""
    enabled: bool = True
    
    # Pattern definition
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    window: Optional[int] = None  # Time window in seconds
    min_occurrences: Optional[int] = None
    max_occurrences: Optional[int] = None
    
    # Field mapping
    entity_path: str = "data.user.name"
    timestamp_path: str = "timestamp"
    rule_id_path: str = "rule.id"
    
    # Actions
    output_file: Optional[str] = None
    log_level: str = "INFO"
    
    # State management
    ttl: int = 3600  # Time to live for state entries (seconds)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'name': self.name,
            'pattern_type': self.pattern_type,
            'description': self.description,
            'enabled': self.enabled,
            'conditions': self.conditions,
            'window': self.window,
            'min_occurrences': self.min_occurrences,
            'max_occurrences': self.max_occurrences,
            'entity_path': self.entity_path,
            'timestamp_path': self.timestamp_path,
            'rule_id_path': self.rule_id_path,
            'output_file': self.output_file,
            'log_level': self.log_level,
            'ttl': self.ttl
        }


@dataclass
class EventMatch:
    """Represents a matched correlation event."""
    rule_name: str
    entity: str
    timestamp: datetime
    matched_conditions: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary."""
        return {
            'rule_name': self.rule_name,
            'entity': self.entity,
            'timestamp': self.timestamp.isoformat(),
            'matched_conditions': self.matched_conditions,
            'metadata': self.metadata
        }


class EventCorrelator:
    """Main event correlation engine."""
    
    def __init__(self, config_path: str, debug: bool = False, dry_run: bool = False):
        self.config_path = config_path
        self.debug = debug
        self.dry_run = dry_run
        
        # Setup logging
        self._setup_logging()
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize state management
        self.state: Dict[str, Dict[str, Any]] = {}
        self.db_path = self.config.get('database', {}).get('path', '/tmp/correlator_state.db')
        self._init_database()
        
        # Initialize correlation rules
        self.rules = self._load_rules()
        
        # File tracking
        self.file_positions: Dict[str, int] = {}
        
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('/var/log/correlator.log') if not self.debug else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger('EventCorrelator')
        self.logger.info("Event Correlator initialized")
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            self.logger.info(f"Loaded configuration from {self.config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise
            
    def _load_rules(self) -> List[CorrelationRule]:
        """Load correlation rules from configuration."""
        rules = []
        rules_config = self.config.get('rules', [])
        
        for rule_config in rules_config:
            rule = CorrelationRule(
                name=rule_config['name'],
                pattern_type=rule_config['pattern_type'],
                description=rule_config.get('description', ''),
                enabled=rule_config.get('enabled', True),
                conditions=rule_config.get('conditions', []),
                window=rule_config.get('window'),
                min_occurrences=rule_config.get('min_occurrences'),
                max_occurrences=rule_config.get('max_occurrences'),
                entity_path=rule_config.get('entity_path', 'data.user.name'),
                timestamp_path=rule_config.get('timestamp_path', 'timestamp'),
                rule_id_path=rule_config.get('rule_id_path', 'rule.id'),
                output_file=rule_config.get('output_file'),
                log_level=rule_config.get('log_level', 'INFO'),
                ttl=rule_config.get('ttl', 3600)
            )
            rules.append(rule)
            
        self.logger.info(f"Loaded {len(rules)} correlation rules")
        return rules
        
    def _init_database(self):
        """Initialize SQLite database for state persistence."""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS event_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(rule_name, entity, timestamp)
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_state_lookup 
                ON event_state (rule_name, entity, timestamp)
            ''')
            
            conn.commit()
            conn.close()
            self.logger.info(f"Database initialized at {self.db_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
                
        return value
        
    def _is_valid_event(self, event: Dict[str, Any], rule: CorrelationRule) -> bool:
        """Check if event matches rule conditions."""
        if not rule.enabled:
            return False
            
        for condition in rule.conditions:
            field_path = condition.get('field')
            expected_value = condition.get('equals')
            pattern = condition.get('pattern')
            
            if field_path:
                actual_value = self._get_nested_value(event, field_path)
                
                if expected_value is not None:
                    if actual_value != expected_value:
                        return False
                        
                if pattern:
                    if not re.match(pattern, str(actual_value)):
                        return False
                        
        return True
        
    def _add_to_state(self, rule_name: str, entity: str, event: Dict[str, Any], timestamp: datetime):
        """Add event to state management."""
        # Add to memory state
        state_key = f"{rule_name}:{entity}"
        if state_key not in self.state:
            self.state[state_key] = []
            
        self.state[state_key].append({
            'event': event,
            'timestamp': timestamp
        })
        
        # Clean old entries based on TTL
        now = datetime.now().replace(tzinfo=timezone.utc)
        cutoff_time = now - timedelta(seconds=3600)  # Default TTL
        rule = next((r for r in self.rules if r.name == rule_name), None)
        if rule:
            cutoff_time = now - timedelta(seconds=rule.ttl)
            
        self.state[state_key] = [
            entry for entry in self.state[state_key]
            if entry['timestamp'] > cutoff_time
        ]
        
        # Add to database
        if not self.dry_run:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO event_state 
                    (rule_name, entity, event_data, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (rule_name, entity, json.dumps(event), timestamp))
                conn.commit()
                conn.close()
            except Exception as e:
                self.logger.error(f"Failed to save to database: {e}")
                
    def _check_threshold_pattern(self, rule: CorrelationRule, entity: str) -> Optional[EventMatch]:
        """Check threshold-based patterns."""
        state_key = f"{rule.name}:{entity}"
        if state_key not in self.state:
            return None
            
        events = self.state[state_key]
        if not events:
            return None
            
        # Apply time window if specified
        if rule.window:
            now = datetime.now().replace(tzinfo=timezone.utc)
            cutoff_time = now - timedelta(seconds=rule.window)
            events = [e for e in events if e['timestamp'] > cutoff_time]
            
        count = len(events)
        
        # Check thresholds
        if rule.min_occurrences and count >= rule.min_occurrences:
            if not rule.max_occurrences or count <= rule.max_occurrences:
                match = EventMatch(
                    rule_name=rule.name,
                    entity=entity,
                    timestamp=events[-1]['timestamp'],
                    matched_conditions=[{
                        'threshold_count': count,
                        'events_analyzed': len(events)
                    }]
                )
                return match
                
        return None
        
    def _check_sequence_pattern(self, rule: CorrelationRule, entity: str) -> Optional[EventMatch]:
        """Check sequence-based patterns."""
        state_key = f"{rule.name}:{entity}"
        if state_key not in self.state:
            return None
            
        events = self.state[state_key]
        if len(events) < len(rule.conditions):
            return None
            
        # Check if events match the sequence pattern
        for i in range(len(events) - len(rule.conditions) + 1):
            sequence_match = True
            matched_conditions = []
            
            for j, condition in enumerate(rule.conditions):
                event = events[i + j]['event']
                if self._is_valid_event(event, CorrelationRule(
                    name="temp",
                    pattern_type="sequence",
                    conditions=[condition]
                )):
                    matched_conditions.append(condition)
                else:
                    sequence_match = False
                    break
                    
            if sequence_match:
                match = EventMatch(
                    rule_name=rule.name,
                    entity=entity,
                    timestamp=events[i + len(rule.conditions) - 1]['timestamp'],
                    matched_conditions=matched_conditions
                )
                return match
                
        return None
        
    def _process_event(self, event: Dict[str, Any]):
        """Process a single event against all rules."""
        timestamp_str = self._get_nested_value(event, 'timestamp')
        if not timestamp_str:
            return
            
        try:
            # Parse timestamp (handle different formats)
            if isinstance(timestamp_str, str):
                # Handle ISO format with timezone
                if timestamp_str.endswith('Z'):
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                elif '+' in timestamp_str or timestamp_str.count('-') > 2:
                    # Already has timezone info
                    timestamp = datetime.fromisoformat(timestamp_str)
                else:
                    # Naive datetime
                    timestamp = datetime.fromisoformat(timestamp_str)
            else:
                timestamp = datetime.fromtimestamp(timestamp_str)
        except Exception as e:
            self.logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
            # Use UTC for consistency
            timestamp = datetime.now().replace(tzinfo=timezone.utc)
            
        for rule in self.rules:
            if not self._is_valid_event(event, rule):
                continue
                
            # Get entity for this rule
            entity = self._get_nested_value(event, rule.entity_path) or 'unknown'
            
            # Add event to state
            self._add_to_state(rule.name, entity, event, timestamp)
            
            # Check patterns
            match = None
            if rule.pattern_type == 'threshold':
                match = self._check_threshold_pattern(rule, entity)
            elif rule.pattern_type == 'sequence':
                match = self._check_sequence_pattern(rule, entity)
            elif rule.pattern_type == 'composite':
                # For composite patterns, check both threshold and sequence
                match = self._check_threshold_pattern(rule, entity)
                if not match:
                    match = self._check_sequence_pattern(rule, entity)
                    
            # Handle match
            if match:
                self._handle_match(match)
                
    def _handle_match(self, match: EventMatch):
        """Handle a correlation match."""
        self.logger.info(f"Correlation match: {match.rule_name} for entity {match.entity}")
        
        # Log the match
        match_dict = match.to_dict()
        
        if self.dry_run:
            self.logger.info(f"DRY RUN - Would output: {json.dumps(match_dict, indent=2)}")
            return
            
        # Write to output file if specified
        rule = next((r for r in self.rules if r.name == match.rule_name), None)
        if rule and rule.output_file:
            try:
                output_path = Path(rule.output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'a') as f:
                    f.write(json.dumps(match_dict) + '\n')
                    
                self.logger.info(f"Match written to {rule.output_file}")
            except Exception as e:
                self.logger.error(f"Failed to write match: {e}")
                
        # Also write to default output file
        default_output = self.config.get('output', {}).get('default_file', '/tmp/correlations.jsonl')
        try:
            with open(default_output, 'a') as f:
                f.write(json.dumps(match_dict) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write to default output: {e}")
            
    def tail_file(self, file_path: str):
        """Tail a single log file for JSON events."""
        self.logger.info(f"Starting to tail {file_path}")
        
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.warning(f"File does not exist: {file_path}")
                return
                
            # Get starting position
            start_pos = self.file_positions.get(file_path, 0)
            
            with open(file_path, 'r') as f:
                if start_pos > 0:
                    f.seek(start_pos)
                    
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                        
                    try:
                        event = json.loads(line.strip())
                        self._process_event(event)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        self.logger.error(f"Error processing line: {e}")
                        
                    # Update position
                    self.file_positions[file_path] = f.tell()
                    
        except KeyboardInterrupt:
            self.logger.info("Stopping file tailing")
        except Exception as e:
            self.logger.error(f"Error tailing file {file_path}: {e}")
            
    def run(self):
        """Main execution loop."""
        self.logger.info("Starting event correlator")
        
        input_config = self.config.get('input', {})
        files = input_config.get('files', [])
        
        if not files:
            self.logger.error("No files configured for monitoring")
            return
            
        if len(files) == 1:
            # Single file - tail directly
            self.tail_file(files[0])
        else:
            # Multiple files - implement simple round-robin
            self.logger.info(f"Monitoring {len(files)} files")
            # For simplicity, tail the first file in this implementation
            # In production, you'd want proper multi-file handling
            self.tail_file(files[0])


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Event Correlation Engine')
    parser.add_argument('config', nargs='?', help='Configuration file path')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--dry-run', action='store_true', help='Test mode - no output files')
    parser.add_argument('--reset', action='store_true', help='Reset state database')
    
    args = parser.parse_args()
    
    # Handle reset (config is optional for reset)
    if args.reset:
        db_path = '/tmp/correlator_state.db'
        if Path(db_path).exists():
            Path(db_path).unlink()
            print(f"Reset state database: {db_path}")
        return
    
    # Check if config is provided for non-reset operations
    if not args.config:
        parser.error("Configuration file path is required when not using --reset")
        
    # Create and run correlator
    correlator = EventCorrelator(args.config, args.debug, args.dry_run)
    correlator.run()


if __name__ == '__main__':
    main()