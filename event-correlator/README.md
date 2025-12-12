# Event Correlation Engine

A lightweight, production-ready event correlation engine designed for security monitoring and threat detection. Built as part of the Security-Enhancement platform, it provides advanced pattern detection capabilities for correlating security events from multiple sources.

## 🚀 Quick Start (5 minutes)

```bash
# 1. Install dependencies
cd /home/engine/project/event-correlator
pip install -r requirements.txt

# 2. Test with sample data
./test_patterns.sh dry-run

# 3. Run with your own configuration
python3 correlator.py config.yaml

# 4. Check output
tail -f /tmp/correlations.jsonl
```

That's it! The correlation engine is now running and detecting patterns in your events.

## 📋 Overview

The Event Correlation Engine is designed to:

- **Tail JSON events** from log files in real-time
- **Detect complex patterns** using sequence and threshold matching
- **Maintain state** with in-memory storage and SQLite persistence
- **Handle file rotation** gracefully without losing events
- **Support YAML configuration** for easy rule management
- **Run in multiple modes**: normal, debug, dry-run, test, and reset

### Key Features

- **Lightweight**: Single Python script with minimal dependencies (PyYAML only)
- **Production-Ready**: Comprehensive error handling, logging, and monitoring
- **Scalable**: Efficient state management with TTL and cleanup
- **Flexible**: YAML-driven configuration for custom correlation rules
- **Robust**: Handles JSON parsing errors, file rotation, and system restarts
- **Extensible**: Easy to add new correlation patterns and integrations

### Supported Pattern Types

1. **Threshold Patterns**: Detect events that occur N times within a time window
2. **Sequence Patterns**: Detect specific sequences of events in order
3. **Composite Patterns**: Combine threshold and sequence logic

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Event Correlation Engine                │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────┐ │
│  │   File Tailing  │  │   State Mgmt    │  │ Rule     │ │
│  │                 │  │                 │  │ Engine   │ │
│  │ • JSON parsing  │  │ • In-memory     │  │          │ │
│  │ • File rotation │  │ • SQLite persist│  │ • Pattern│ │
│  │ • Error handling│  │ • TTL cleanup   │  │   match  │ │
│  └─────────────────┘  └─────────────────┘  └──────────┘ │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────┐ │
│  │ Configuration   │  │ Output Handler  │  │ Logging  │ │
│  │                 │  │                 │  │          │ │
│  │ • YAML loading  │  │ • JSONL output  │  │ • Debug  │ │
│  │ • Rule validation│  │ • File rotation│  │ • Error  │ │
│  │ • Dynamic reload │  │ • Alerting     │  │ • Info   │ │
│  └─────────────────┘  └─────────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │        Output Files         │
              │                             │
              │ • /tmp/correlations.jsonl   │
              │ • /tmp/brute_force_alerts   │
              │ • Custom rule outputs       │
              └─────────────────────────────┘
```

## 📦 Installation

Choose the installation method that best fits your environment.

### Method 1: Manual Installation

```bash
# Clone or navigate to the event-correlator directory
cd /home/engine/project/event-correlator

# Install dependencies
pip install -r requirements.txt

# Make script executable
chmod +x correlator.py

# Test installation
python3 correlator.py --help
```

### Method 2: Systemd Service Installation

```bash
# Install the correlator package
cd /home/engine/project/event-correlator
pip install -e .

# Create system user
sudo useradd -r -s /bin/false correlator

# Create directories
sudo mkdir -p /opt/event-correlator /var/log
sudo chown correlator:correlator /opt/event-correlator /var/log

# Copy files
sudo cp correlator.py config.yaml /opt/event-correlator/
sudo cp systemd/correlator.service /etc/systemd/system/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable correlator
sudo systemctl start correlator

# Check status
sudo systemctl status correlator
```

### Method 3: Docker Installation

```bash
# Build image
cd /home/engine/project/event-correlator
docker build -t event-correlator .

# Run container
docker run -d \
  --name correlator \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v /var/log:/var/log \
  event-correlator

# View logs
docker logs correlator

# Stop container
docker stop correlator
docker rm correlator
```

### Method 4: Development Installation

```bash
# Install in development mode
cd /home/engine/project/event-correlator
pip install -e .

# Run tests
./test_patterns.sh

# Install pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

## ⚙️ Configuration Guide

The correlation engine uses YAML configuration files to define input sources, correlation rules, and output destinations.

### Basic Configuration Structure

```yaml
# Input configuration
input:
  files:
    - /var/log/wazuh/active-responses.log
    - /tmp/security_events.jsonl
  poll_interval: 1

# Output configuration
output:
  default_file: /tmp/correlations.jsonl
  format: jsonl

# Database configuration
database:
  path: /tmp/correlator_state.db

# Correlation rules
rules:
  - name: "brute_force_detection"
    pattern_type: "threshold"
    conditions:
      - field: "data.event_type"
        equals: "ssh_login"
      - field: "data.status"
        equals: "failed"
    window: 300
    min_occurrences: 5
    entity_path: "data.srcip"
```

### Input Configuration

```yaml
input:
  files:
    - /var/log/wazuh/active-responses.log  # File to monitor
    - /tmp/security_events.jsonl
  poll_interval: 1  # Seconds between polls (default: 1)
```

**Supported options:**
- `files`: List of files to monitor for JSON events
- `poll_interval`: Polling frequency in seconds (default: 1)

### Output Configuration

```yaml
output:
  default_file: /tmp/correlations.jsonl  # Default output file
  format: jsonl  # Output format (jsonl or json)
```

**Supported options:**
- `default_file`: Default file for correlation matches
- `format`: Output format (`jsonl` or `json`)

### Rule Configuration

#### Threshold Patterns

```yaml
rules:
  - name: "ssh_brute_force"
    pattern_type: "threshold"
    description: "Detect SSH brute force attacks"
    enabled: true
    conditions:
      - field: "data.event_type"
        equals: "ssh_login"
      - field: "data.status"
        equals: "failed"
    window: 300  # Time window in seconds
    min_occurrences: 5  # Minimum occurrences to trigger
    max_occurrences: 50  # Maximum occurrences before reset
    entity_path: "data.srcip"  # Field to group events by
    timestamp_path: "timestamp"  # Field containing timestamp
    ttl: 3600  # Time to live for state entries
    output_file: /tmp/brute_force_alerts.jsonl
```

#### Sequence Patterns

```yaml
rules:
  - name: "lateral_movement"
    pattern_type: "sequence"
    description: "Detect lateral movement"
    conditions:
      - field: "data.event_type"
        equals: "ssh_login"
      - field: "data.event_type"
        equals: "file_access"
      - field: "data.event_type"
        equals: "command_execution"
    window: 900  # Maximum time between events
    entity_path: "data.user.name"
    timestamp_path: "timestamp"
```

#### Composite Patterns

```yaml
rules:
  - name: "privilege_escalation"
    pattern_type: "composite"
    description: "Detect privilege escalation"
    conditions:
      - field: "data.rule.category"
        pattern: ".*privilege.*"
      - field: "data.program"
        pattern: ".*(sudo|su).*"
    window: 600
    min_occurrences: 2  # Threshold component
    entity_path: "data.user.name"
    timestamp_path: "timestamp"
```

### Field Path Configuration

Event correlation uses dot notation to access nested fields:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "user": {
      "name": "john",
      "id": 1000
    },
    "srcip": "192.168.1.100"
  },
  "rule": {
    "id": "5715",
    "level": 3
  }
}
```

**Field paths:**
- `timestamp` → `"2024-01-15T10:30:00Z"`
- `data.user.name` → `"john"`
- `data.srcip` → `"192.168.1.100"`
- `rule.id` → `"5715"`

### Condition Types

#### Equals Condition

```yaml
- field: "data.event_type"
  equals: "ssh_login"
```

#### Pattern Condition (Regex)

```yaml
- field: "data.srcip"
  pattern: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"
```

#### Not Equals Condition

```yaml
- field: "data.srcip"
  not_equals: "127.0.0.1"
```

#### Multiple Conditions

```yaml
conditions:
  - field: "data.event_type"
    equals: "ssh_login"
  - field: "data.status"
    equals: "failed"
  - field: "data.srcip"
    pattern: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"
    not_equals: "127.0.0.1"
```

## 🚀 Running Modes

The correlation engine supports several running modes for different use cases:

### Normal Mode (Production)

```bash
python3 correlator.py config.yaml
```

Standard operation with logging to `/var/log/correlator.log`.

### Debug Mode

```bash
python3 correlator.py config.yaml --debug
```

Enhanced logging to console for troubleshooting and development.

### Dry-Run Mode

```bash
python3 correlator.py config.yaml --dry-run
```

Test mode that processes events but doesn't write output files. Perfect for testing configurations.

### Reset Mode

```bash
python3 correlator.py --reset
```

Clear all stored state and start fresh.

### Test Mode

```bash
./test_patterns.sh
```

Comprehensive test suite for validation.

### Service Mode

```bash
# Start as systemd service
sudo systemctl start correlator

# Check service status
sudo systemctl status correlator

# View service logs
sudo journalctl -u correlator -f
```

## 📊 Sample Events

The event correlator expects JSON events with a specific structure. Here's an example from Wazuh:

```json
{
  "timestamp": "2024-01-15T10:30:15Z",
  "rule": {
    "id": "5715",
    "level": 3,
    "description": "Attempted login by user."
  },
  "agent": {
    "id": "001",
    "name": "webserver-01"
  },
  "data": {
    "srcip": "192.168.1.100",
    "srcport": "45231",
    "dstip": "192.168.1.10",
    "dstport": "22",
    "user": "admin",
    "event_type": "ssh_login",
    "status": "failed"
  }
}
```

### Required Fields

- `timestamp`: Event timestamp (ISO format or Unix timestamp)
- At least one condition field to match against

### Optional Fields

- `data.*`: Application-specific data
- `rule.*`: Rule/alert information
- `agent.*`: Source agent information

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. JSON Parsing Errors

**Symptom:** `JSONDecodeError: Expecting ',' delimiter`

**Solution:**
```bash
# Check file format
head -5 /var/log/your_log_file.log

# Ensure each line is valid JSON
python3 -c "
import json
with open('/var/log/your_log_file.log') as f:
    for i, line in enumerate(f, 1):
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            print(f'Line {i}: {e}')
"
```

#### 2. File Permission Errors

**Symptom:** `PermissionError: [Errno 13] Permission denied`

**Solution:**
```bash
# Check permissions
ls -la /var/log/your_log_file.log

# Fix permissions
sudo chown correlator:correlator /var/log/your_log_file.log
sudo chmod 644 /var/log/your_log_file.log

# For systemd service, ensure user has access
sudo usermod -a -G adm correlator
```

#### 3. Memory Issues

**Symptom:** High memory usage or out of memory errors

**Solution:**
```yaml
# Reduce memory usage in config
performance:
  max_memory_mb: 256
  cleanup_interval: 300

# Increase TTL cleanup
rules:
  - name: "example"
    ttl: 1800  # Reduce from 3600 to 1800
```

#### 4. No Correlations Detected

**Symptom:** Engine runs but no matches found

**Debug:**
```bash
# Run in debug mode
python3 correlator.py config.yaml --debug

# Check event format
python3 -c "
import json
with open('your_log_file.log') as f:
    line = f.readline()
    event = json.loads(line)
    print('Event structure:')
    print(json.dumps(event, indent=2))
    print('\\nField paths:')
    def find_paths(obj, prefix=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f'{prefix}.{k}' if prefix else k
                print(f'  {path}')
                find_paths(v, path)
        elif isinstance(obj, list) and obj:
            find_paths(obj[0], f'{prefix}[0]')
    find_paths(event)
"

# Test configuration
python3 -c "
import yaml
with open('config.yaml') as f:
    config = yaml.safe_load(f)
    for rule in config['rules']:
        print(f'Rule: {rule[\"name\"]}')
        print(f'  Pattern: {rule[\"pattern_type\"]}')
        print(f'  Conditions: {len(rule[\"conditions\"])}')
"
```

#### 5. Database Lock Issues

**Symptom:** `database is locked` errors

**Solution:**
```bash
# Kill any existing processes
pkill -f correlator

# Remove stale database
rm /tmp/correlator_state.db

# Restart with fresh database
python3 correlator.py config.yaml
```

#### 6. File Rotation Issues

**Symptom:** Missing events after log rotation

**Solution:**
```bash
# Configure logrotate properly
sudo tee /etc/logrotate.d/your-app > /dev/null << EOF
/var/log/your_log_file.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload your-app
    endscript
}
EOF
```

### Performance Tuning

#### High-Volume Event Processing

```yaml
# Optimize for high throughput
performance:
  batch_size: 500  # Process more events per batch
  max_memory_mb: 1024  # Allow more memory
  cleanup_interval: 60  # More frequent cleanup

input:
  poll_interval: 0.5  # More frequent polling
```

#### Low-Resource Environments

```yaml
# Optimize for limited resources
performance:
  batch_size: 50
  max_memory_mb: 128
  cleanup_interval: 600

input:
  poll_interval: 5  # Less frequent polling
```

### Log Analysis

#### Check Correlation Engine Logs

```bash
# View real-time logs
tail -f /var/log/correlator.log

# Check error logs
grep ERROR /var/log/correlator.log

# Analyze pattern matches
grep "Correlation match" /var/log/correlator.log

# Performance metrics
grep "events processed" /var/log/correlator.log
```

#### Check Output Files

```bash
# View correlations
tail -f /tmp/correlations.jsonl

# Analyze correlation types
cat /tmp/correlations.jsonl | jq '.rule_name' | sort | uniq -c

# Check specific rule output
tail -f /tmp/brute_force_alerts.jsonl
```

## 🔌 Wazuh Integration

The Event Correlation Engine integrates seamlessly with Wazuh. See the comprehensive integration guide in [`examples/wazuh_integration.md`](examples/wazuh_integration.md) for detailed setup instructions.

### Quick Wazuh Setup

1. **Active Response Integration** (Recommended)
2. **Socket Output Integration**
3. **Webhook Integration**
4. **Direct Log File Monitoring**

See the integration guide for step-by-step instructions and examples.

## 📈 Example Configurations

The repository includes pre-built configurations for common security scenarios:

### Brute Force Detection

```bash
python3 correlator.py examples/config_brute_force.yaml --debug
```

**Detects:**
- SSH brute force attacks
- Web application brute force
- Database brute force
- Password spraying
- Successful brute force
- Rapid login attempts
- Geographic anomalies

### Lateral Movement Detection

```bash
python3 correlator.py examples/config_lateral_move.yaml --debug
```

**Detects:**
- SSH lateral movement
- Network scanning
- Privilege escalation + file access
- Command execution patterns
- Service discovery
- Credential harvesting
- Windows lateral movement
- Pass-the-hash attacks

## 🏥 Health Monitoring

### System Service Health

```bash
# Check service status
sudo systemctl status correlator

# Restart service
sudo systemctl restart correlator

# View logs
sudo journalctl -u correlator -f
```

### Application Health

The correlation engine provides several health indicators:

1. **Log File Monitoring**: Check `/var/log/correlator.log` for errors
2. **Output File Activity**: Monitor `/tmp/correlations.jsonl` for new entries
3. **Database Size**: Check SQLite database size for memory usage
4. **Process Health**: Monitor CPU and memory usage

### Automated Health Checks

```bash
#!/bin/bash
# health_check.sh

LOG_FILE="/var/log/correlator.log"
OUTPUT_FILE="/tmp/correlations.jsonl"
DB_FILE="/tmp/correlator_state.db"

# Check if files exist and are being updated
if [ -f "$LOG_FILE" ]; then
    if [ $(find "$LOG_FILE" -mmin -5 | wc -l) -gt 0 ]; then
        echo "✓ Log file is being updated"
    else
        echo "✗ Log file not updated recently"
    fi
fi

if [ -f "$OUTPUT_FILE" ]; then
    if [ $(find "$OUTPUT_FILE" -mmin -5 | wc -l) -gt 0 ]; then
        echo "✓ Output file is being updated"
    else
        echo "✗ Output file not updated recently"
    fi
fi

# Check database
if [ -f "$DB_FILE" ]; then
    DB_SIZE=$(du -h "$DB_FILE" | cut -f1)
    echo "Database size: $DB_SIZE"
fi

# Check for errors in logs
ERROR_COUNT=$(grep -c "ERROR" "$LOG_FILE" 2>/dev/null || echo "0")
if [ "$ERROR_COUNT" -gt 10 ]; then
    echo "✗ High error count: $ERROR_COUNT"
else
    echo "✓ Error count acceptable: $ERROR_COUNT"
fi
```

## 🔒 Security Considerations

### Production Deployment

1. **User Permissions**
   ```bash
   # Create dedicated user
   sudo useradd -r -s /bin/false -d /opt/event-correlator correlator
   sudo usermod -a -G security correlator
   ```

2. **File Permissions**
   ```bash
   # Secure configuration
   sudo chown correlator:correlator /opt/event-correlator/*
   sudo chmod 640 /opt/event-correlator/config.yaml
   ```

3. **Systemd Security**
   ```ini
   [Service]
   User=correlator
   Group=correlator
   NoNewPrivileges=yes
   PrivateTmp=yes
   ProtectSystem=strict
   ```

### Data Protection

1. **Log Retention**
   ```bash
   # Configure log rotation
   sudo tee /etc/logrotate.d/correlator > /dev/null << EOF
   /var/log/correlator.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
   }
   /tmp/*_correlations.jsonl {
       daily
       rotate 7
       compress
   }
   EOF
   ```

2. **Database Encryption**
   ```python
   # For sensitive environments, consider encrypting the database
   # or using secure temporary storage
   ```

## 🚀 Advanced Usage

### Custom Rule Development

```yaml
rules:
  - name: "custom_detection"
    pattern_type: "composite"
    description: "Custom security detection"
    conditions:
      - field: "data.event_type"
        equals: "login_attempt"
      - field: "data.user.role"
        equals: "admin"
    window: 3600
    min_occurrences: 1
    entity_path: "data.user.name"
    timestamp_path: "timestamp"
    ttl: 7200
    output_file: "/custom/alerts/custom_detection.jsonl"
    log_level: "DEBUG"
```

### Multiple Configuration Files

```bash
# Run with specific configuration
python3 correlator.py /path/to/custom_config.yaml

# Use environment-specific configs
python3 correlator.py configs/production.yaml
python3 correlator.py configs/staging.yaml
```

### Integration with SIEM

```bash
# Send alerts to SIEM via webhook
curl -X POST https://your-siem.com/api/alerts \
  -H "Content-Type: application/json" \
  -d @/tmp/correlations.jsonl

# Or use file monitoring
tail -f /tmp/correlations.jsonl | \
  while read line; do
    echo "$line" | nc siem-server 514
  done
```

## 📚 API Reference

### Command Line Interface

```bash
python3 correlator.py [CONFIG] [OPTIONS]

Arguments:
  CONFIG              Configuration file path

Options:
  --debug             Enable debug logging
  --dry-run          Test mode - no output files
  --reset            Reset state database
  --help, -h         Show this help message
```

### Configuration File Format

See the [Configuration Guide](#configuration-guide) section above for detailed YAML configuration options.

### Output Format

Correlations are output in JSONL format (one JSON object per line):

```json
{
  "rule_name": "ssh_brute_force",
  "entity": "192.168.1.100",
  "timestamp": "2024-01-15T10:35:00Z",
  "matched_conditions": [
    {
      "threshold_count": 5,
      "events_analyzed": 5
    }
  ],
  "metadata": {
    "source_file": "/var/log/wazuh/active-responses.log",
    "pattern_type": "threshold"
  }
}
```

### Database Schema

The SQLite database stores event state with the following schema:

```sql
CREATE TABLE event_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    entity TEXT NOT NULL,
    event_data TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(rule_name, entity, timestamp)
);

CREATE INDEX idx_state_lookup 
ON event_state (rule_name, entity, timestamp);
```

## 🤝 Contributing

We welcome contributions! Please see the main Security-Enhancement repository guidelines.

### Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd security-enhancement/event-correlator

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8 mypy

# Run tests
./test_patterns.sh

# Run linting
black --check correlator.py
flake8 correlator.py
mypy correlator.py
```

### Testing

```bash
# Run all tests
./test_patterns.sh all

# Run specific test
./test_patterns.sh dry-run
./test_patterns.sh patterns
./test_patterns.sh state
./test_patterns.sh config
```

## 📄 License

This project is part of the Security-Enhancement repository and follows the same licensing terms.

## 🆘 Support

For support and questions:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review the logs in `/var/log/correlator.log`
3. Test with sample data using `./test_patterns.sh`
4. Check the Wazuh integration guide for specific integration issues
5. Open an issue in the Security-Enhancement repository

## 📋 Changelog

### Version 1.0.0

- Initial release
- JSON event tailing and correlation
- Threshold and sequence pattern matching
- In-memory state with SQLite persistence
- YAML-driven configuration
- Wazuh integration support
- Production-ready logging and error handling
- Comprehensive test suite
- Documentation and examples

---

**Event Correlation Engine** - Part of the Security-Enhancement platform for advanced threat detection and correlation.