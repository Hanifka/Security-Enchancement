# Agent Service - Log Parser

A comprehensive log parsing and aggregation module for Linux system logs.

## Features

- **Multi-format Support**: Parses multiple Linux log formats
  - `/var/log/audit/audit.log` (auditd)
  - `/var/log/syslog` (syslog)
  - `/var/log/auth.log` (authentication logs)
  - `/var/log/yum.log` (YUM package manager)
  
- **Flexible Filtering**: Filter logs by:
  - Time range (start_time, end_time)
  - Keywords (case-insensitive)
  - Process IDs (PIDs)
  - Maximum entries per source

- **Normalized Output**: All log formats are parsed into a unified `LogEntry` dataclass with:
  - Timestamp
  - Source (log file path)
  - Host
  - Process name
  - PID
  - Message
  - Raw line
  - Format-specific metadata

- **Configurable Paths**: Override default log paths via:
  - Config dictionary
  - Environment variables (`LOG_PATH_AUDIT`, `LOG_PATH_SYSLOG`, etc.)
  
- **Robust Error Handling**: Gracefully handles missing files, permission errors, and malformed entries

## Installation

```bash
# Install from the project root
pip install -e .

# Or just ensure the agent_service package is in your Python path
```

## Usage

### Basic Usage

```python
from agent_service import collect_logs

# Collect all logs from default locations
results = collect_logs()

# Print summary
for log_type, data in results.items():
    print(f"{log_type}: {data['count']} entries from {data['path']}")
```

### Filtering by Time Range

```python
from datetime import datetime, timedelta
from agent_service import collect_logs

# Get logs from the last hour
end_time = datetime.now()
start_time = end_time - timedelta(hours=1)

results = collect_logs(
    start_time=start_time,
    end_time=end_time
)

for log_type, data in results.items():
    print(f"\n{log_type} - {data['count']} entries:")
    for entry in data['entries'][:5]:  # Print first 5
        print(f"  {entry.timestamp} [{entry.process}] {entry.message[:80]}")
```

### Filtering by Keywords

```python
from agent_service import collect_logs

# Search for SSH-related activity
results = collect_logs(
    keywords=["ssh", "sshd"],
    max_entries=100
)

for entry in results.get('auth', {}).get('entries', []):
    print(f"{entry.timestamp} - {entry.message}")
```

### Filtering by Process IDs

```python
from agent_service import collect_logs

# Monitor specific processes
results = collect_logs(
    pids=[1234, 5678],
    max_entries=50
)

for log_type, data in results.items():
    for entry in data['entries']:
        print(f"[{entry.process}:{entry.pid}] {entry.message}")
```

### Combined Filtering

```python
from datetime import datetime, timedelta
from agent_service import collect_logs

# Complex query: sudo commands in the last 24 hours
results = collect_logs(
    start_time=datetime.now() - timedelta(days=1),
    end_time=datetime.now(),
    keywords=["sudo", "COMMAND"],
    max_entries=100
)

for log_type, data in results.items():
    print(f"\n{log_type}: {data['count']} sudo commands")
    for entry in data['entries']:
        print(f"  {entry.timestamp} {entry.host} - {entry.message}")
```

### Custom Log Paths

```python
from agent_service import collect_logs

# Override default paths
custom_paths = {
    'audit': '/custom/path/audit.log',
    'syslog': '/var/log/messages',
    'auth': '/custom/auth.log'
}

results = collect_logs(log_paths=custom_paths)
```

### Using Environment Variables

```bash
# Set custom paths via environment
export LOG_PATH_AUDIT=/custom/audit.log
export LOG_PATH_SYSLOG=/custom/syslog
export LOG_PATH_AUTH=/custom/auth.log
export LOG_PATH_YUM=/custom/yum.log
```

```python
from agent_service import collect_logs

# Automatically uses environment variable paths
results = collect_logs()
```

### Direct Parser Usage

```python
from agent_service.log_parser import AuditLogParser, SyslogParser
from datetime import datetime, timedelta

# Use a specific parser directly
parser = AuditLogParser('/var/log/audit/audit.log')

# Parse with filters
entries = parser.parse_file(
    start_time=datetime.now() - timedelta(hours=1),
    keywords=["execve"],
    max_entries=50
)

for entry in entries:
    print(f"{entry.timestamp}: {entry.message}")
    print(f"  Type: {entry.metadata.get('type')}")
    print(f"  PID: {entry.pid}, Process: {entry.process}")
```

## Log Entry Structure

Each parsed log entry is returned as a `LogEntry` dataclass:

```python
@dataclass
class LogEntry:
    timestamp: datetime        # Parsed timestamp
    source: str               # Source log file path
    host: Optional[str]       # Hostname (if available)
    process: Optional[str]    # Process name
    pid: Optional[int]        # Process ID
    message: str              # Log message content
    raw_line: str            # Original log line
    metadata: Dict[str, str] # Format-specific metadata
```

### Example Log Entry

```python
LogEntry(
    timestamp=datetime(2024, 1, 15, 10, 30, 45),
    source='/var/log/auth.log',
    host='webserver',
    process='sshd',
    pid=10001,
    message='Failed password for invalid user admin from 10.0.0.50',
    raw_line='Jan 15 10:30:45 webserver sshd[10001]: Failed password...',
    metadata={}
)
```

## Supported Log Formats

### Audit Log (auditd)

```
type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 ...
```

Extracts:
- Timestamp from audit message
- Event type (SYSCALL, PATH, EXECVE, etc.)
- PID and comm (process name) from message
- Serial number

### Syslog / Auth Log

Traditional format:
```
Jan 15 10:30:45 hostname process[1234]: message text
```

ISO format:
```
2024-01-15T10:30:45.123456+00:00 hostname process[1234]: message text
```

Extracts:
- Timestamp (supports both formats)
- Hostname
- Process name
- PID (if present)

### YUM Log

```
Jan 15 10:30:45 Installed: package-name-1.2.3.el7.x86_64
```

Extracts:
- Timestamp
- Action (Installed, Updated, Erased)
- Package name

## Configuration Priority

Log paths are resolved in the following order (highest to lowest priority):

1. `log_paths` parameter to `collect_logs()`
2. Environment variables (`LOG_PATH_AUDIT`, etc.)
3. Default paths (`/var/log/audit/audit.log`, etc.)

## Error Handling

The log parser gracefully handles:

- **Missing files**: Skipped without errors
- **Permission denied**: Skipped without errors
- **Malformed lines**: Skipped, valid lines are still processed
- **Invalid timestamps**: Entry skipped
- **Unicode characters**: Properly handled
- **Very long lines**: No truncation or errors

## Performance Considerations

- **Streaming**: Files are read line-by-line (not loaded entirely into memory)
- **Early termination**: Stops reading when `max_entries` is reached
- **Efficient filtering**: Applied during parsing, not after

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python3 -m pytest tests/test_log_parser.py -v

# Run specific test class
python3 -m pytest tests/test_log_parser.py::TestAuditLogParser -v

# Run with coverage
python3 -m pytest tests/test_log_parser.py --cov=agent_service
```

## Examples

### Security Monitoring

```python
from agent_service import collect_logs
from datetime import datetime, timedelta

# Monitor for failed login attempts
results = collect_logs(
    start_time=datetime.now() - timedelta(hours=24),
    keywords=["failed", "failure", "invalid user"],
    log_paths={'auth': '/var/log/auth.log'}
)

failed_logins = results.get('auth', {}).get('entries', [])
print(f"Failed login attempts in last 24 hours: {len(failed_logins)}")

# Group by source IP
from collections import Counter
ips = []
for entry in failed_logins:
    import re
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', entry.message)
    if match:
        ips.append(match.group(1))

print("\nTop attacking IPs:")
for ip, count in Counter(ips).most_common(10):
    print(f"  {ip}: {count} attempts")
```

### Package Change Tracking

```python
from agent_service import collect_logs

# Track package installations/updates
results = collect_logs(
    log_paths={'yum': '/var/log/yum.log'}
)

for entry in results.get('yum', {}).get('entries', []):
    action = entry.metadata.get('action', 'Unknown')
    print(f"{entry.timestamp} - {action}: {entry.message}")
```

### Audit Trail

```python
from agent_service import collect_logs

# Track all execve system calls (command executions)
results = collect_logs(
    keywords=["execve"],
    log_paths={'audit': '/var/log/audit/audit.log'},
    max_entries=1000
)

for entry in results.get('audit', {}).get('entries', []):
    print(f"{entry.timestamp} - Process: {entry.process} (PID: {entry.pid})")
    print(f"  {entry.message[:100]}")
```

## Contributing

When adding support for new log formats:

1. Create a new parser class inheriting from `LogParser`
2. Implement the `parse_line()` method
3. Add regex patterns for the log format
4. Update `get_parser_for_log_type()` to handle the new type
5. Add comprehensive tests in `tests/test_log_parser.py`

## License

See the main project LICENSE file.
