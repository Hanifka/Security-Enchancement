# Linux Detection Engineering Agent

A comprehensive Linux security monitoring and detection engineering platform built with auditd, Sysmon for Linux, and a FastAPI backend. This agent provides real-time log analysis, threat detection, and a web-based dashboard for security testing and investigation.

## Overview

The Linux Detection Engineering Agent is a full-stack security detection platform that combines:

- **auditd Framework**: Kernel-level audit logging with extensive rule coverage
- **Sysmon for Linux**: System monitoring with MITRE ATT&CK-mapped detection rules
- **FastAPI Backend**: RESTful API for log ingestion, parsing, and analysis
- **Web Dashboard**: Interactive interface for executing detection payloads and analyzing results
- **Log Parser**: Intelligent parser that correlates auditd and Sysmon events with custom detection logic

This platform is designed for security engineers who need to:
- Test detection rules against simulated attack scenarios
- Understand system activity through structured log analysis
- Develop and validate security monitoring configurations
- Generate detection engineering payloads for threat hunting

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Web Dashboard (Frontend)              │
│              • Agent selection interface                │
│              • Payload execution controls               │
│              • Real-time log group viewing              │
│              • Result analysis and export               │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP/WebSocket
┌──────────────────────▼──────────────────────────────────┐
│            FastAPI Backend (REST API)                   │
│  • /agents - List and select agents                    │
│  • /payloads - List available detection payloads        │
│  • /execute - Run payloads and collect events           │
│  • /logs - Query and filter audit logs                  │
│  • /results - Retrieve structured detection results     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                   Log Parser & Analyzer                 │
│  • auditd event parsing and normalization              │
│  • Sysmon XML to structured format conversion           │
│  • Event correlation and enrichment                     │
│  • Detection rule evaluation                            │
│  • Result caching in static/results directory           │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│           Linux Kernel Monitoring Layer                 │
│  • auditd daemon (kernel audit framework)              │
│  • Sysmon for Linux (process/file/network monitoring)   │
│  • System logs (/var/log/audit/*, /var/log/sysmon)     │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites & Dependencies

### System Requirements

- **OS**: Ubuntu 16.04, 18.04, 20.04, 22.04, or 24.04 (other Debian-based systems may work)
- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum (8GB+ for active monitoring)
- **Disk**: 20GB+ for log storage (adjustable based on monitoring intensity)

### Required Packages

**System Packages:**
```bash
sudo apt-get update
sudo apt-get install -y \
    python3.10 \
    python3-pip \
    curl \
    wget \
    git \
    build-essential
```

**Python Dependencies:**
- fastapi (0.104+)
- uvicorn (0.24+)
- pydantic (2.0+)
- python-dateutil
- requests

These are managed via `requirements.txt` and installed automatically during setup.

### Log Access Requirements

The agent requires read access to system logs:

```bash
# auditd logs (usually requires sudo)
/var/log/audit/audit.log

# Sysmon logs (if Sysmon for Linux is deployed)
/var/log/sysmon.log

# Standard system logs
/var/log/auth.log
/var/log/syslog
```

To allow non-root access to audit logs (optional but recommended):

```bash
sudo usermod -a -G adm $(whoami)
sudo usermod -a -G audit $(whoami)
# Log out and log back in for group changes to take effect
```

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd Security-Enhancement
```

### 2. Install auditd (If Not Already Present)

The repository includes an offline installer for multiple Ubuntu versions:

```bash
cd install_auditd
chmod +x install_auditd_offline.sh
sudo ./install_auditd_offline.sh
```

This script will:
- Auto-detect your Ubuntu version
- Install the appropriate auditd and libauparse packages
- Enable the auditd service
- Load custom audit rules from `auditd_rules.conf`

### 3. Verify auditd Installation

```bash
sudo systemctl status auditd
sudo ausearch -m config -m rule_list
```

### 4. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 5. Configure Log Paths (Optional)

Edit `config.yaml` to specify custom log paths:

```yaml
audit_log_path: "/var/log/audit/audit.log"
sysmon_log_path: "/var/log/sysmon.log"
auth_log_path: "/var/log/auth.log"
syslog_path: "/var/log/syslog"
```

## Agent Service - Log Parser Module

The `agent_service` package provides a powerful log parsing and aggregation module that can load and normalize entries from multiple Linux log sources.

### Features

- **Multi-format Support**: Parses auditd, syslog, auth.log, and yum.log files
- **Flexible Filtering**: Filter by time range, keywords, PIDs, and max entries
- **Normalized Output**: All log formats are parsed into a unified `LogEntry` structure
- **Configurable Paths**: Override default log paths via config dict or environment variables
- **Robust Error Handling**: Gracefully handles missing files and permission errors

### Basic Usage

```python
from agent_service import collect_logs
from datetime import datetime, timedelta

# Collect all recent logs
results = collect_logs(
    start_time=datetime.now() - timedelta(hours=1),
    keywords=["ssh", "sudo"],
    max_entries=100
)

# Process results
for log_type, data in results.items():
    print(f"{log_type}: {data['count']} entries")
    for entry in data['entries']:
        print(f"  {entry.timestamp} [{entry.process}] {entry.message}")
```

### Environment Variable Configuration

```bash
export LOG_PATH_AUDIT=/var/log/audit/audit.log
export LOG_PATH_SYSLOG=/var/log/syslog
export LOG_PATH_AUTH=/var/log/auth.log
export LOG_PATH_YUM=/var/log/yum.log
```

### Running Tests

```bash
# Run all log parser tests
python3 -m pytest tests/test_log_parser.py -v

# Run with coverage
python3 -m pytest tests/test_log_parser.py --cov=agent_service
```

### Example Script

A comprehensive example script is provided:

```bash
PYTHONPATH=/home/engine/project python3 agent_service/example_usage.py
```

For detailed documentation, see [agent_service/README.md](agent_service/README.md).

## Starting the Service

### Quick Start

```bash
./start_agent.sh
```

This script will:
1. Verify Python dependencies
2. Ensure auditd is running
3. Check log file accessibility
4. Start the FastAPI backend on `http://localhost:8000`
5. Launch the web dashboard on `http://localhost:3000`

### Manual Start (Backend Only)

```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Manual Start (with Custom Port)

```bash
./start_agent.sh --port 8080
```

### Background Execution

```bash
./start_agent.sh --daemon
# Or with nohup
nohup ./start_agent.sh > agent.log 2>&1 &
```

## Web Dashboard

The Security Monitoring Dashboard provides a web-based interface for executing payloads and analyzing log results. The dashboard is built with FastAPI backend and Bootstrap frontend.

### Starting the Dashboard

#### Quick Start

```bash
# Using the provided startup script
./start_dashboard.sh
```

#### Manual Start

```bash
# Create virtual environment (if not exists)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python3 main.py
```

The dashboard will be available at:
- **Main Dashboard**: http://localhost:8000/dashboard/
- **API Documentation**: http://localhost:8000/docs
- **API Root**: http://localhost:8000/

### Dashboard Features

#### 1. Agent Selection

- **Dropdown Selector**: Choose from available monitoring agents
- **Status Indicators**: Online/offline status for each agent
- **Agent Information**: Display agent names and IDs
- **Real-time Updates**: Agent status updates every 30 seconds

#### 2. Payload Creation and Execution

- **Command Input**: Textarea for entering commands to execute
- **Description Field**: Optional description for payload documentation
- **Execute Button**: Run payloads with real-time progress feedback
- **Next Payload**: Reset form for creating new payloads
- **Loading States**: Visual feedback during payload execution

#### 3. Results Analysis

##### Log Summary Cards
- **Per-log-type Counts**: AUDITD, SYSLOG, AUTH.LOG, YUM, etc.
- **Color-coded Badges**: Visual indicators for data availability
- **Path Information**: Source file paths for each log type
- **Responsive Layout**: Grid layout adapting to screen size

##### Command Metadata
- **Timestamp**: Execution time with local formatting
- **Duration**: Execution time in milliseconds
- **Agent Information**: Selected agent details
- **Status Indicators**: Success/failure/pending status

##### Standard Output/Error
- **STDOUT Display**: Command output in formatted text area
- **STDERR Display**: Error messages with highlighting
- **Scrollable Areas**: Large output handling with scroll bars
- **Monospace Font**: Preserved formatting for technical output

##### Log Entries Accordion
- **Collapsible Panels**: Organized by log type (AUDITD, SYSLOG, etc.)
- **Entry Counts**: Number of entries per log type
- **Formatted Display**: Timestamp, process, PID, and message formatting
- **Hover Effects**: Interactive highlighting of log entries
- **Limited Display**: Shows first 50 entries to prevent performance issues

#### 4. Payload History Sidebar

- **Chronological List**: Recent payloads sorted by timestamp
- **Status Indicators**: Visual status badges (completed, failed, running)
- **Command Preview**: Truncated command display for quick identification
- **Click to Load**: Load previous payload results by clicking history items
- **Agent Information**: Shows which agent executed each payload
- **Empty State**: Helpful message when no history exists

#### 5. Export Functionality

- **JSON Export**: Download complete payload data as JSON file
- **Automatic Naming**: Files named with payload ID for uniqueness
- **Complete Data**: Includes all metadata, logs, and execution details
- **Browser Download**: Standard browser download interface

#### 6. Connection Status

- **Real-time Indicator**: Shows API connection status
- **Auto-recovery**: Automatic reconnection attempts
- **Visual Feedback**: Color-coded status indicators
- **Error Handling**: Graceful degradation when API unavailable

### API Endpoints

The dashboard uses these REST API endpoints:

#### Agents
```bash
GET /api/agents          # List all available agents
```

#### Payloads
```bash
GET /api/payloads        # List payload history
POST /api/payloads       # Create and execute new payload
GET /api/payloads/{id}   # Get specific payload details
GET /api/payloads/{id}/export  # Export payload as JSON
```

#### Static Files
```bash
GET /dashboard/          # Main dashboard interface
GET /dashboard/static/*  # Static assets (CSS, JS, images)
```

### Example Workflow

1. **Start the Dashboard**
   ```bash
   ./start_dashboard.sh
   ```

2. **Open Browser**
   Navigate to http://localhost:8000/dashboard/

3. **Select Agent**
   Choose an online agent from the dropdown (e.g., "Security Monitor Alpha")

4. **Create Payload**
   - Enter command: `ls -la /var/log`
   - Add description: "List log directory contents"
   - Click "Execute"

5. **Monitor Execution**
   - Watch loading indicator
   - Wait for completion (typically 1-5 seconds)

6. **Review Results**
   - Check log summary cards for data collected
   - Review command metadata and output
   - Expand log entries accordion to examine detailed logs
   - Export results if needed

7. **Create Next Payload**
   - Click "Next Payload" to reset form
   - Enter new command and repeat process

### Error Handling

- **Connection Errors**: Modal dialogs for API failures
- **Validation Errors**: Form validation with helpful messages
- **Execution Failures**: Clear error display and retry options
- **Empty States**: Helpful guidance when no data exists
- **Timeout Handling**: 30-second timeouts with user feedback

### Performance Considerations

- **Log Limiting**: Maximum 100 entries per log type to prevent browser overload
- **Periodic Updates**: 30-second intervals for history updates
- **Lazy Loading**: Results loaded on-demand
- **Responsive Design**: Optimized for desktop and mobile viewing
- **Caching**: Browser caching for static assets

### Security Notes

- **Command Validation**: Basic validation for command inputs
- **Safe Execution**: Limited command set for demonstration
- **Output Sanitization**: HTML escaping for log display
- **No Persistent Storage**: In-memory storage for demo purposes
- **Local Access**: Default configuration for localhost only

## Bundled Example Payloads

The agent includes predefined payloads for common detection scenarios:

### File System Monitoring Payloads

**payload_file_modification.json** - Tests file modification detection
- Targets: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- Expected Events: File write access by unauthorized users
- MITRE: T1548 (Abuse Elevation Control Mechanism)

**payload_file_deletion.json** - Tests file deletion logging
- Targets: Log files, temporary files
- Expected Events: Deletion attempts with user context
- MITRE: T1070 (Indicator Removal)

### Command Execution Monitoring Payloads

**payload_execve.json** - Tests command execution capture
- Simulates: Privileged command execution
- Expected Events: execve syscalls with full command context
- MITRE: T1548 (Privilege Escalation)

**payload_sudo_usage.json** - Tests sudo access logging
- Simulates: sudo command invocation
- Expected Events: sudoers file access, sudo execution
- MITRE: T1548 (Use Elevated Control Mechanism)

### Identity & Authentication Payloads

**payload_identity_changes.json** - Tests user/group modification logging
- Simulates: useradd, usermod, groupadd commands
- Expected Events: /etc/passwd and /etc/group modifications
- MITRE: T1078 (Valid Accounts)

**payload_sudo_group_changes.json** - Tests sudoers modification detection
- Simulates: Modifying /etc/sudoers and /etc/sudoers.d
- Expected Events: Sudoers file access with write flag
- MITRE: T1548 (Privilege Escalation)

### Time & Locale Payloads

**payload_time_change.json** - Tests system time modification logging
- Simulates: Date/time adjustments via adjtimex, settimeofday, clock_settime
- Expected Events: Time-related system calls and /etc/localtime modifications
- MITRE: T1070 (Indicator Removal on Host)

**payload_system_locale.json** - Tests locale and system configuration changes
- Simulates: Changes to /etc/issue, system locale settings
- Expected Events: Configuration file modifications
- MITRE: T1082 (System Information Discovery)

### Network Monitoring Payloads

**payload_network_connection.json** - Tests network activity logging (Sysmon)
- Simulates: Outbound connections from common tools (wget, curl, ssh)
- Expected Events: NetworkConnect events with destination IP/port
- MITRE: T1041 (Exfiltration Over C2 Channel)

**payload_suspicious_process.json** - Tests process creation rules
- Simulates: Execution of suspicious shells and interpreters
- Expected Events: ProcessCreate events with parent/child relationships
- MITRE: T1059 (Command and Scripting Interpreter)

### Privilege Escalation Payloads

**payload_setuid_abuse.json** - Tests setuid/setgid detection
- Simulates: chmod commands setting setuid bits
- Expected Events: File permission changes, execve with elevated privileges
- MITRE: T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)

## Static Results Directory

The agent stores all execution results in the `static/results/` directory:

```
static/results/
├── 2024-01-15/
│   ├── payload_execve_123456.json
│   ├── payload_sudo_123457.json
│   └── summary_2024-01-15.json
├── 2024-01-16/
│   ├── payload_identity_123458.json
│   └── summary_2024-01-16.json
└── index.json  # Master index of all results
```

### Result File Format

Each result file contains:

```json
{
  "execution_id": "payload_execve_123456",
  "timestamp": "2024-01-15T14:32:45.123Z",
  "payload_type": "execve",
  "agent_id": "combined_agent_1",
  "status": "completed",
  "duration_seconds": 5.234,
  "events_captured": 47,
  "detection_rules_matched": 12,
  "log_groups": [
    {
      "group_id": "process_creation_1",
      "event_type": "ProcessCreate",
      "count": 5,
      "rules_matched": ["T1059.004", "T1548"],
      "events": [...]
    }
  ],
  "performance_metrics": {
    "parsing_time_ms": 345,
    "correlation_time_ms": 123,
    "analysis_time_ms": 89
  }
}
```

### Accessing Results via API

```bash
# Get all results from a specific date
curl http://localhost:8000/results?date=2024-01-15

# Get a specific result
curl http://localhost:8000/results/payload_execve_123456

# Export result as CSV
curl http://localhost:8000/results/payload_execve_123456?format=csv > export.csv

# Get summary statistics
curl http://localhost:8000/results/summary?date_range=7d
```

### Cleanup & Retention

To manage disk space:

```bash
# Delete results older than 30 days
./manage_results.sh --cleanup --days 30

# Archive results to compressed format
./manage_results.sh --archive --before 2024-01-01

# Get disk usage statistics
./manage_results.sh --stats
```

## API Examples for Integrations

The FastAPI backend provides a comprehensive REST API for integrations with SIEM, ticketing systems, and custom tools.

### Authentication

API requests use header-based authentication:

```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:8000/api/...
```

Generate API keys in the dashboard Settings > API Management.

### Core API Endpoints

#### 1. List Available Agents

```bash
curl http://localhost:8000/api/agents

# Response:
{
  "agents": [
    {
      "id": "auditd_agent_1",
      "name": "auditd Agent",
      "status": "active",
      "monitoring_sources": ["auditd"],
      "last_event": "2024-01-15T14:35:22Z"
    },
    {
      "id": "sysmon_agent_1",
      "name": "Sysmon Agent",
      "status": "active",
      "monitoring_sources": ["sysmon"],
      "last_event": "2024-01-15T14:35:18Z"
    }
  ]
}
```

#### 2. List Available Payloads

```bash
curl http://localhost:8000/api/payloads?filter=file

# Response:
{
  "payloads": [
    {
      "id": "payload_file_modification",
      "name": "File Modification Detection",
      "description": "Tests file modification detection",
      "category": "file_system",
      "mitre_techniques": ["T1548", "T1070"],
      "parameters": [
        {
          "name": "target_file",
          "type": "string",
          "required": true,
          "default": "/etc/passwd"
        }
      ]
    }
  ]
}
```

#### 3. Execute a Payload

```bash
curl -X POST http://localhost:8000/api/execute \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "combined_agent_1",
    "payload_id": "payload_execve",
    "parameters": {
      "timeout_seconds": 30,
      "logging_level": "debug"
    }
  }'

# Response:
{
  "execution_id": "payload_execve_789456",
  "status": "running",
  "progress": 0,
  "estimated_completion": "2024-01-15T14:35:45Z"
}
```

#### 4. Poll Execution Status

```bash
curl http://localhost:8000/api/executions/payload_execve_789456

# Response:
{
  "execution_id": "payload_execve_789456",
  "status": "completed",
  "progress": 100,
  "events_captured": 52,
  "detection_rules_matched": 14,
  "completed_at": "2024-01-15T14:35:42Z"
}
```

#### 5. Query Logs by Execution

```bash
curl "http://localhost:8000/api/logs?execution_id=payload_execve_789456&event_type=ProcessCreate"

# Response:
{
  "logs": [
    {
      "timestamp": "2024-01-15T14:35:30.456Z",
      "event_type": "ProcessCreate",
      "pid": 12345,
      "process_name": "/bin/bash",
      "user": "root",
      "command_line": "/bin/bash -c 'id'",
      "parent_pid": 12340,
      "parent_name": "/usr/bin/sudo",
      "detection_rules_matched": ["T1059.004"]
    }
  ],
  "total_count": 8,
  "page": 1,
  "page_size": 50
}
```

#### 6. Export Results

```bash
# Export as JSON
curl "http://localhost:8000/api/results/payload_execve_789456/export?format=json" \
  > results.json

# Export as CSV
curl "http://localhost:8000/api/results/payload_execve_789456/export?format=csv" \
  > results.csv

# Export with filtering
curl "http://localhost:8000/api/results/payload_execve_789456/export?format=json&event_types=ProcessCreate,FileCreate" \
  > results_filtered.json
```

#### 7. Create Custom Detection Rule

```bash
curl -X POST http://localhost:8000/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Suspicious Shell Execution",
    "description": "Detect unexpected shell spawning",
    "event_types": ["ProcessCreate"],
    "conditions": [
      {
        "field": "process_name",
        "operator": "contains",
        "value": "/bin/bash"
      },
      {
        "field": "parent_name",
        "operator": "not_in",
        "value": ["/bin/login", "/bin/ssh", "/bin/konsole"]
      }
    ],
    "severity": "high",
    "mitre_technique": "T1059.004"
  }'

# Response:
{
  "rule_id": "custom_rule_001",
  "status": "created",
  "enabled": true
}
```

#### 8. Webhook Integration for Real-Time Alerts

```bash
# Register a webhook for high-severity detections
curl -X POST http://localhost:8000/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-siem.example.com/api/events",
    "event_filter": "severity:high",
    "headers": {
      "Authorization": "Bearer your-token",
      "X-Custom-Header": "value"
    }
  }'

# Response:
{
  "webhook_id": "webhook_001",
  "status": "active",
  "test_result": "success"
}
```

### Integration Examples

#### SIEM Integration (Wazuh)

```bash
# Forward high-severity detections to Wazuh
curl -X POST http://localhost:8000/api/integrations/wazuh \
  -H "Content-Type: application/json" \
  -d '{
    "manager_host": "wazuh-manager.example.com",
    "manager_port": 1514,
    "agent_name": "linux-detection-agent",
    "min_severity": "high"
  }'
```

#### Ticketing System Integration (Jira)

```bash
# Auto-create Jira tickets for critical detections
curl -X POST http://localhost:8000/api/integrations/jira \
  -H "Content-Type: application/json" \
  -d '{
    "jira_url": "https://jira.example.com",
    "project_key": "SEC",
    "issue_type": "Security Incident",
    "min_severity": "critical",
    "auto_create": true
  }'
```

## Safety Considerations

### ⚠️ Important: Running Commands on Production Systems

This agent can execute potentially destructive operations as part of detection payloads:

**DO NOT run this agent on production systems without proper testing and approval.**

### Safe Practices

1. **Test Environment First**
   - Always test payloads in isolated environments
   - Use VMs or containers for initial testing
   - Validate detection rules before production deployment

2. **Privilege Levels**
   - The agent should not run as root unless necessary
   - Use minimal required privileges (audit group for log access)
   - Never grant sudo access to the agent user unnecessarily

3. **Payload Selection**
   - Review payload parameters before execution
   - Understand the system impact before running
   - Some payloads (e.g., `payload_time_change.json`) modify system state

4. **Staging Payloads**
   - Run payloads during maintenance windows
   - Notify system administrators before execution
   - Have rollback procedures ready

5. **Log Retention**
   - Ensure audit logs are backed up before testing
   - Configure log rotation to prevent disk fullness
   - Archive results regularly to protect audit trail

6. **Credential Handling**
   - Store API keys securely (use environment variables or vaults)
   - Rotate API keys regularly
   - Never commit credentials to version control

7. **Access Control**
   - Restrict dashboard access to authorized users
   - Use firewall rules to limit API access
   - Enable audit logging for all agent operations

## Configuring Alternate Log Paths

By default, the agent monitors standard system log locations. You can configure it to monitor alternate paths.

### Configuration File

Edit `config.yaml`:

```yaml
# Standard log paths
audit_log_path: "/var/log/audit/audit.log"
sysmon_log_path: "/var/log/sysmon.log"
auth_log_path: "/var/log/auth.log"
syslog_path: "/var/log/syslog"

# For monitoring alternate locations (e.g., forwarded logs)
additional_log_paths:
  - path: "/mnt/remote-logs/audit.log"
    type: "auditd"
    enabled: true
  - path: "/opt/custom-logging/security.log"
    type: "sysmon"
    enabled: false
  - path: "/var/log/forensics/preserved.log"
    type: "auditd"
    enabled: true

# Log parsing options
parser_options:
  follow_symlinks: true
  max_file_size_gb: 100
  buffer_size_mb: 512
  parse_timeout_seconds: 30
```

### Environment Variables

Override log paths via environment variables:

```bash
export AUDIT_LOG_PATH="/path/to/audit.log"
export SYSMON_LOG_PATH="/path/to/sysmon.log"
export CUSTOM_LOG_PATHS="/path1/log.txt,/path2/log.txt"

./start_agent.sh
```

### Command-Line Arguments

Override paths when starting the agent:

```bash
python3 app/main.py \
  --audit-log /var/log/audit/audit.log \
  --sysmon-log /var/log/sysmon.log \
  --additional-logs /opt/logs/security.log,/mnt/archived/events.log
```

### Remote Log Access

To monitor logs on remote systems:

1. **SSH-based forwarding:**
   ```bash
   ssh remote-host tail -f /var/log/audit/audit.log | \
     python3 -c "import sys; [handle_line(line) for line in sys.stdin]"
   ```

2. **Syslog forwarding:**
   ```bash
   # Configure rsyslog on remote host to forward to agent
   # Add to /etc/rsyslog.conf on remote:
   *.* @@agent-host:514
   ```

3. **Log aggregation service:**
   - Configure Filebeat, Logstash, or similar to ingest logs from the agent API

### Verify Log Access

```bash
# Check if agent can read configured log paths
./scripts/verify_log_access.sh

# Output example:
# ✓ /var/log/audit/audit.log (readable)
# ✓ /var/log/sysmon.log (readable)
# ✗ /opt/custom/logs/security.log (permission denied)
```

## Troubleshooting

### Agent Won't Start

```bash
# Check Python version
python3 --version  # Should be 3.10+

# Check dependencies
pip3 show fastapi uvicorn

# Verify auditd is running
sudo systemctl status auditd

# Check port availability
netstat -an | grep 8000
```

### Can't Read Audit Logs

```bash
# Verify permissions
ls -la /var/log/audit/audit.log

# Add user to audit group
sudo usermod -a -G audit $USER
sudo usermod -a -G adm $USER

# Re-login for groups to take effect
logout && login
```

### No Events Detected

```bash
# Check if audit rules are loaded
sudo augenrules --list

# Reload rules if needed
sudo augenrules --load

# Generate test event
sudo auditctl -m test

# Search for it
sudo ausearch -m USER_AUDIT
```

## Additional Resources

- **MITRE ATT&CK Framework**: https://attack.mitre.org
- **auditd Documentation**: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing
- **Sysmon for Linux**: https://github.com/Sysinternals/SysmonForLinux
- **FastAPI Documentation**: https://fastapi.tiangolo.com

## Contributing

Contributions are welcome! Please submit issues and pull requests for:
- New detection payloads
- Additional MITRE ATT&CK coverage
- Parser improvements
- Dashboard enhancements

## License

This project is provided as-is for security research and educational purposes.
