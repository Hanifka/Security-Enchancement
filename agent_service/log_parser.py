"""
Log parser module for parsing and aggregating Linux system logs.

Supports multiple log formats:
- /var/log/audit/audit.log (auditd format)
- /var/log/syslog (syslog format)
- /var/log/auth.log (auth log format)
- /var/log/yum.log (yum package manager)
"""

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Union


@dataclass
class LogEntry:
    """Normalized log entry structure."""
    timestamp: datetime
    source: str
    host: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    message: str = ""
    raw_line: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)


class LogParser:
    """Base class for parsing different log formats."""
    
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.source_name = log_path
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line. Override in subclasses."""
        raise NotImplementedError
    
    def parse_file(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        keywords: Optional[List[str]] = None,
        pids: Optional[List[int]] = None,
        max_entries: Optional[int] = None
    ) -> List[LogEntry]:
        """Parse log file with filtering."""
        if not self.log_path.exists():
            return []
        
        entries = []
        keywords_lower = [k.lower() for k in keywords] if keywords else []
        pids_set = set(pids) if pids else None
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if not line:
                        continue
                    
                    entry = self.parse_line(line)
                    if not entry:
                        continue
                    
                    # Apply timestamp filter
                    if start_time and entry.timestamp < start_time:
                        continue
                    if end_time and entry.timestamp > end_time:
                        continue
                    
                    # Apply PID filter
                    if pids_set and (entry.pid is None or entry.pid not in pids_set):
                        continue
                    
                    # Apply keyword filter
                    if keywords_lower:
                        line_lower = line.lower()
                        if not any(kw in line_lower for kw in keywords_lower):
                            continue
                    
                    entries.append(entry)
                    
                    # Check max entries limit
                    if max_entries and len(entries) >= max_entries:
                        break
        
        except (IOError, PermissionError) as e:
            # Gracefully skip files that can't be read
            pass
        
        return entries


class AuditLogParser(LogParser):
    """Parser for /var/log/audit/audit.log."""
    
    # Example: type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=...
    AUDIT_PATTERN = re.compile(
        r'^type=(?P<type>\S+)\s+msg=audit\((?P<timestamp>[\d.]+):(?P<serial>\d+)\):\s*(?P<message>.*)$'
    )
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        match = self.AUDIT_PATTERN.match(line)
        if not match:
            return None
        
        try:
            timestamp_float = float(match.group('timestamp'))
            timestamp = datetime.fromtimestamp(timestamp_float)
        except (ValueError, OSError):
            return None
        
        message = match.group('message')
        metadata = {'type': match.group('type'), 'serial': match.group('serial')}
        
        # Try to extract PID from message
        pid = None
        pid_match = re.search(r'\bpid=(\d+)', message)
        if pid_match:
            pid = int(pid_match.group(1))
        
        # Try to extract comm (command/process name)
        process = None
        comm_match = re.search(r'\bcomm="([^"]+)"', message)
        if comm_match:
            process = comm_match.group(1)
        
        return LogEntry(
            timestamp=timestamp,
            source=self.source_name,
            process=process,
            pid=pid,
            message=message,
            raw_line=line,
            metadata=metadata
        )


class SyslogParser(LogParser):
    """Parser for /var/log/syslog and /var/log/auth.log."""
    
    # Example: Jan 15 10:30:45 hostname process[1234]: message text
    # Example: 2024-01-15T10:30:45.123456+00:00 hostname process[1234]: message text
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            return None
        
        timestamp_str = match.group('timestamp')
        
        # Try ISO format first
        try:
            if 'T' in timestamp_str:
                # Handle ISO format with timezone
                if '.' in timestamp_str:
                    # With microseconds
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                # Handle traditional syslog format (no year)
                current_year = datetime.now().year
                timestamp_with_year = f"{current_year} {timestamp_str}"
                timestamp = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except (ValueError, AttributeError):
            return None
        
        pid = None
        if match.group('pid'):
            try:
                pid = int(match.group('pid'))
            except ValueError:
                pass
        
        return LogEntry(
            timestamp=timestamp,
            source=self.source_name,
            host=match.group('host'),
            process=match.group('process'),
            pid=pid,
            message=match.group('message'),
            raw_line=line
        )


class YumLogParser(LogParser):
    """Parser for /var/log/yum.log."""
    
    # Example: Jan 15 10:30:45 Installed: package-name-1.2.3-4.el7.x86_64
    YUM_PATTERN = re.compile(
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<action>\w+):\s*(?P<message>.*)$'
    )
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        match = self.YUM_PATTERN.match(line)
        if not match:
            return None
        
        timestamp_str = match.group('timestamp')
        
        try:
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            timestamp = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        
        action = match.group('action')
        message = match.group('message')
        
        return LogEntry(
            timestamp=timestamp,
            source=self.source_name,
            process='yum',
            message=message,
            raw_line=line,
            metadata={'action': action}
        )


# Default log locations
DEFAULT_LOG_PATHS = {
    'audit': '/var/log/audit/audit.log',
    'syslog': '/var/log/syslog',
    'auth': '/var/log/auth.log',
    'yum': '/var/log/yum.log',
}

# Environment variable overrides
ENV_VAR_PREFIX = 'LOG_PATH_'


def get_log_paths(config: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Get log paths from config dict or environment variables.
    
    Priority:
    1. config dict parameter
    2. Environment variables (LOG_PATH_AUDIT, LOG_PATH_SYSLOG, etc.)
    3. Default paths
    
    Args:
        config: Optional dictionary mapping log type to path
        
    Returns:
        Dictionary mapping log type to file path
    """
    paths = DEFAULT_LOG_PATHS.copy()
    
    # Check environment variables
    for log_type in paths.keys():
        env_var = f"{ENV_VAR_PREFIX}{log_type.upper()}"
        env_path = os.environ.get(env_var)
        if env_path:
            paths[log_type] = env_path
    
    # Config dict takes highest priority
    if config:
        paths.update(config)
    
    return paths


def get_parser_for_log_type(log_type: str, log_path: str) -> LogParser:
    """Get appropriate parser for log type."""
    if log_type == 'audit':
        return AuditLogParser(log_path)
    elif log_type in ('syslog', 'auth'):
        return SyslogParser(log_path)
    elif log_type == 'yum':
        return YumLogParser(log_path)
    else:
        # Default to syslog parser for unknown types
        return SyslogParser(log_path)


def collect_logs(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    keywords: Optional[List[str]] = None,
    pids: Optional[List[int]] = None,
    max_entries: Optional[int] = 1000,
    log_paths: Optional[Dict[str, str]] = None
) -> Dict[str, Dict[str, Union[int, List[LogEntry]]]]:
    """
    Collect and aggregate logs from multiple sources.
    
    Args:
        start_time: Filter logs after this timestamp (inclusive)
        end_time: Filter logs before this timestamp (inclusive)
        keywords: List of keywords to filter messages (case-insensitive)
        pids: List of process IDs to filter
        max_entries: Maximum entries to return per log source
        log_paths: Optional dict mapping log type to file path
        
    Returns:
        Dictionary keyed by log source with structure:
        {
            'log_type': {
                'count': int,
                'entries': List[LogEntry],
                'path': str
            }
        }
    """
    paths = get_log_paths(log_paths)
    results = {}
    
    for log_type, log_path in paths.items():
        parser = get_parser_for_log_type(log_type, log_path)
        
        entries = parser.parse_file(
            start_time=start_time,
            end_time=end_time,
            keywords=keywords,
            pids=pids,
            max_entries=max_entries
        )
        
        # Only include sources that have entries or exist
        if entries or Path(log_path).exists():
            results[log_type] = {
                'count': len(entries),
                'entries': entries,
                'path': log_path
            }
    
    return results
