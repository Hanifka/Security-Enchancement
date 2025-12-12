# Wazuh Integration Guide

This guide explains how to integrate the Event Correlation Engine with Wazuh using 4 different methods.

## Overview

The Event Correlation Engine can consume events from Wazuh to perform advanced correlation and detection. Wazuh can forward events to the correlator in several ways:

1. **Active Response** - Use Wazuh's active response capability to send events
2. **Socket Output** - Forward events through Unix sockets
3. **Webhook Integration** - Send events via HTTP webhooks
4. **Log File Monitoring** - Monitor Wazuh log files directly

## Method 1: Active Response Integration

### Setup Active Response in Wazuh

Add this configuration to your Wazuh manager's `ossec.conf`:

```xml
<active-response>
  <disabled>no</disabled>
  <command>send_to_correlator</command>
  <location>all</location>
  <level>3</level>
  <timeout>300</timeout>
</active-response>
```

### Create Active Response Script

Create `/var/ossec/active-response/bin/send_to_correlator.sh`:

```bash
#!/bin/bash

# Send event to correlation engine
LOG_FILE="/tmp/correlator_input.log"
EVENT_DATA=$1

# Format event for correlation engine
echo "${EVENT_DATA}" >> "${LOG_FILE}"

# Optional: Send to socket
echo "${EVENT_DATA}" | nc -w 1 localhost 9999
```

Set proper permissions:
```bash
chmod +x /var/ossec/active-response/bin/send_to_correlator.sh
chown root:ossec /var/ossec/active-response/bin/send_to_correlator.sh
```

### Configure Correlation Engine

Update your `config.yaml`:

```yaml
input:
  files:
    - /tmp/correlator_input.log
  poll_interval: 1
```

## Method 2: Socket Output Integration

### Wazuh Socket Configuration

Add to `ossec.conf`:

```xml
<socket>
  <name>correlation</name>
  <location>/tmp/correlator.socket</location>
  <mode>bind</mode>
</socket>
```

### Send Events via Socket

Create a simple socket listener in Python:

```python
#!/usr/bin/env python3
import socket
import json
import sys

def start_socket_listener(socket_path, output_file):
    """Listen on Unix socket and write to file"""
    try:
        # Remove socket if exists
        import os
        if os.path.exists(socket_path):
            os.remove(socket_path)
            
        # Create socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(socket_path)
        sock.listen(1)
        
        while True:
            conn, addr = sock.accept()
            data = conn.recv(4096).decode('utf-8')
            if data:
                with open(output_file, 'a') as f:
                    f.write(data + '\n')
            conn.close()
            
    except Exception as e:
        print(f"Socket error: {e}", file=sys.stderr)
        
if __name__ == '__main__':
    start_socket_listener('/tmp/correlator.socket', '/tmp/wazuh_events.log')
```

### Configure Correlation Engine

```yaml
input:
  files:
    - /tmp/wazuh_events.log
  poll_interval: 1
```

## Method 3: Webhook Integration

### Create Webhook Receiver

Create `/var/ossec/etc/webhook_correlator.sh`:

```bash
#!/bin/bash

# Receive POST data and forward to correlation engine
EVENT_DATA=$(cat)

# Write to log file for correlation engine to monitor
echo "${EVENT_DATA}" >> /tmp/wazuh_webhook_events.log

# Log to syslog for auditing
logger -t wazuh-correlator "Webhook event received"

# HTTP response
echo "HTTP/1.1 200 OK"
echo "Content-Type: application/json"
echo "Connection: close"
echo '{"status": "received"}'
```

### Configure Wazuh Webhook

In `ossec.conf`, add custom alerts:

```xml
<osquery_config>
  <integration>
    <name>webhook</name>
    <hook_url>http://localhost:8080/webhook</hook_url>
    <level>3</level>
    <timeout>300</timeout>
  </integration>
</osquery_config>
```

### Start Webhook Server

Use a simple HTTP server:

```python
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Write to file for correlation engine
        with open('/tmp/wazuh_webhook_events.log', 'a') as f:
            f.write(post_data.decode('utf-8') + '\n')
            
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "success"}')
        
if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), WebhookHandler)
    server.serve_forever()
```

## Method 4: Direct Log File Monitoring

### Configure Wazuh to Write JSON Events

Modify Wazuh to write formatted events:

Create `/var/ossec/etc/wazuh_correlator_formatter.py`:

```python
#!/usr/bin/env python3
import json
import sys
import datetime

def format_wazuh_event(line):
    """Format Wazuh event for correlation engine"""
    try:
        # Parse the line if it's not already JSON
        if line.strip().startswith('{'):
            event = json.loads(line.strip())
        else:
            # Create basic event structure
            event = {
                'timestamp': datetime.datetime.now().isoformat(),
                'message': line.strip(),
                'source': 'wazuh',
                'level': 'info'
            }
            
        return event
    except Exception as e:
        return None

if __name__ == '__main__':
    for line in sys.stdin:
        formatted = format_wazuh_event(line)
        if formatted:
            print(json.dumps(formatted))
```

### Monitor Wazuh Log Files Directly

Configure the correlation engine to monitor Wazuh log files:

```yaml
input:
  files:
    - /var/ossec/logs/alerts/alerts.log
    - /var/ossec/logs/active-responses.log
    - /var/ossec/logs/fim/events.log
  poll_interval: 5
```

## Complete Configuration Example

Here's a complete configuration that combines multiple methods:

```yaml
# Wazuh Integration Configuration
input:
  files:
    - /var/ossec/logs/alerts/alerts.log
    - /tmp/correlator_input.log
    - /tmp/wazuh_events.log
  poll_interval: 1

output:
  default_file: /tmp/wazuh_correlations.jsonl
  format: jsonl

database:
  path: /var/lib/correlator/wazuh_state.db

rules:
  # Brute force detection from Wazuh
  - name: "wazuh_brute_force"
    pattern_type: "threshold"
    description: "Detect brute force from Wazuh alerts"
    enabled: true
    conditions:
      - field: "rule.description"
        pattern: ".*login.*"
      - field: "rule.level"
        greater_than: 3
    window: 300
    min_occurrences: 5
    entity_path: "data.srcip"
    timestamp_path: "timestamp"
    output_file: /var/ossec/logs/brute_force_correlations.log
    
  # Privilege escalation detection
  - name: "wazuh_privilege_escalation"
    pattern_type: "composite"
    description: "Detect privilege escalation from Wazuh"
    enabled: true
    conditions:
      - field: "rule.description"
        pattern: ".*sudo.*"
      - field: "data.user"
        not_equals: "root"
    window: 600
    min_occurrences: 2
    entity_path: "data.user"
    timestamp_path: "timestamp"
    output_file: /var/ossec/logs/privilege_escalation_correlations.log

logging:
  level: INFO
  file: /var/log/correlator_wazuh.log
```

## Testing the Integration

### 1. Test with Sample Events

```bash
# Start the correlation engine
python3 correlator.py config.yaml --debug

# In another terminal, send test events
cat examples/sample_events.jsonl >> /tmp/correlator_input.log

# Check output
tail -f /tmp/wazuh_correlations.jsonl
```

### 2. Verify Wazuh Integration

```bash
# Check if events are being written to log files
tail -f /tmp/correlator_input.log

# Monitor correlation engine logs
tail -f /var/log/correlator_wazuh.log

# Test active response
echo '{"test": "event"}' >> /tmp/correlator_input.log
```

### 3. Validate Correlation Rules

```bash
# Test in dry-run mode
python3 correlator.py config.yaml --dry-run --debug

# Reset state and test
python3 correlator.py config.yaml --reset
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Check file permissions
   ls -la /tmp/correlator_input.log
   
   # Fix permissions
   sudo chown correlator:correlator /tmp/correlator_input.log
   sudo chmod 644 /tmp/correlator_input.log
   ```

2. **Socket Connection Issues**
   ```bash
   # Check if socket exists
   ls -la /tmp/correlator.socket
   
   # Test socket manually
   echo '{"test": "data"}' | nc -w 1 /tmp/correlator.socket
   ```

3. **Log File Monitoring**
   ```bash
   # Verify Wazuh is writing to log files
   tail -f /var/ossec/logs/alerts/alerts.log
   
   # Check correlation engine is reading
   python3 correlator.py config.yaml --debug
   ```

4. **JSON Parsing Errors**
   ```bash
   # Check log format
   head -5 /tmp/correlator_input.log
   
   # Validate JSON
   python3 -c "import json; json.load(open('/tmp/correlator_input.log'))"
   ```

### Performance Optimization

1. **Adjust Poll Intervals**
   ```yaml
   input:
     poll_interval: 2  # Reduce CPU usage
   ```

2. **Memory Management**
   ```yaml
   performance:
     max_memory_mb: 256
     cleanup_interval: 300
   ```

3. **Log Rotation**
   ```bash
   # Configure logrotate for large log files
   echo "/tmp/correlator_input.log {
       daily
       rotate 7
       compress
       delaycompress
       missingok
       notifempty
   }" | sudo tee /etc/logrotate.d/correlator
   ```

## Security Considerations

1. **File Permissions**
   - Use dedicated system user for correlator
   - Restrict file permissions to needed access only
   - Use secure sockets instead of plain files when possible

2. **Network Security**
   - Use HTTPS for webhook endpoints
   - Implement authentication for webhook receivers
   - Restrict socket access with proper permissions

3. **Data Protection**
   - Encrypt sensitive correlation outputs
   - Implement log retention policies
   - Regular backup of state database

## Next Steps

1. Start with Method 4 (Direct Log Monitoring) for simplicity
2. Experiment with different correlation patterns
3. Integrate with your existing SIEM or alerting system
4. Set up monitoring and alerting for the correlation engine itself
5. Customize rules based on your specific threat landscape