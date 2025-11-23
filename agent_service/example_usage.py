#!/usr/bin/env python3
"""
Example usage of the log_parser module.

This script demonstrates various ways to use the log parser for security monitoring.
"""

from datetime import datetime, timedelta
from agent_service import collect_logs


def example_basic_collection():
    """Example: Basic log collection from all sources."""
    print("=" * 70)
    print("Example 1: Basic Log Collection")
    print("=" * 70)
    
    results = collect_logs(max_entries=5)
    
    for log_type, data in results.items():
        print(f"\n{log_type.upper()}: {data['count']} entries from {data['path']}")
        for i, entry in enumerate(data['entries'][:3], 1):
            print(f"  {i}. {entry.timestamp} [{entry.process or 'N/A'}] "
                  f"{entry.message[:60]}...")


def example_time_filtering():
    """Example: Filter logs by time range."""
    print("\n" + "=" * 70)
    print("Example 2: Time-Based Filtering (Last Hour)")
    print("=" * 70)
    
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=1)
    
    results = collect_logs(
        start_time=start_time,
        end_time=end_time,
        max_entries=10
    )
    
    total = sum(data['count'] for data in results.values())
    print(f"\nTotal entries in last hour: {total}")
    
    for log_type, data in results.items():
        if data['count'] > 0:
            print(f"\n{log_type}: {data['count']} entries")


def example_keyword_search():
    """Example: Search for specific keywords."""
    print("\n" + "=" * 70)
    print("Example 3: Keyword Search (SSH/Authentication)")
    print("=" * 70)
    
    results = collect_logs(
        keywords=["ssh", "sshd", "failed", "accepted"],
        max_entries=10
    )
    
    auth_entries = results.get('auth', {}).get('entries', [])
    syslog_entries = results.get('syslog', {}).get('entries', [])
    
    print(f"\nFound {len(auth_entries)} auth log matches")
    print(f"Found {len(syslog_entries)} syslog matches")
    
    for entry in (auth_entries + syslog_entries)[:5]:
        print(f"\n  {entry.timestamp}")
        print(f"  Host: {entry.host}, Process: {entry.process}[{entry.pid or 'N/A'}]")
        print(f"  Message: {entry.message[:80]}")


def example_pid_filtering():
    """Example: Monitor specific process IDs."""
    print("\n" + "=" * 70)
    print("Example 4: PID-Based Filtering")
    print("=" * 70)
    
    # This is just an example - replace with actual PIDs of interest
    pids_to_monitor = [1, 1234, 5678]
    
    results = collect_logs(
        pids=pids_to_monitor,
        max_entries=10
    )
    
    total = sum(data['count'] for data in results.values())
    print(f"\nMonitoring PIDs: {pids_to_monitor}")
    print(f"Total matching entries: {total}")


def example_security_monitoring():
    """Example: Security monitoring use case."""
    print("\n" + "=" * 70)
    print("Example 5: Security Monitoring (Failed Logins & Sudo)")
    print("=" * 70)
    
    # Check for security-relevant events in the last 24 hours
    start_time = datetime.now() - timedelta(days=1)
    
    # Look for failed login attempts
    failed_logins = collect_logs(
        start_time=start_time,
        keywords=["failed", "failure", "invalid user"],
        max_entries=50
    )
    
    # Look for sudo commands
    sudo_commands = collect_logs(
        start_time=start_time,
        keywords=["sudo", "COMMAND"],
        max_entries=50
    )
    
    print(f"\nSecurity events in last 24 hours:")
    
    failed_count = sum(data['count'] for data in failed_logins.values())
    sudo_count = sum(data['count'] for data in sudo_commands.values())
    
    print(f"  - Failed login attempts: {failed_count}")
    print(f"  - Sudo commands executed: {sudo_count}")
    
    # Show some examples
    auth_entries = failed_logins.get('auth', {}).get('entries', [])
    if auth_entries:
        print("\n  Recent failed login attempts:")
        for entry in auth_entries[:3]:
            print(f"    {entry.timestamp} - {entry.message[:70]}")


def example_custom_paths():
    """Example: Using custom log paths."""
    print("\n" + "=" * 70)
    print("Example 6: Custom Log Paths")
    print("=" * 70)
    
    # You can override default paths
    custom_paths = {
        'audit': '/var/log/audit/audit.log',
        'syslog': '/var/log/syslog',
        'auth': '/var/log/auth.log',
        # Add custom log sources
        'custom': '/var/log/custom-app.log',
    }
    
    results = collect_logs(log_paths=custom_paths, max_entries=5)
    
    print("\nChecking custom log paths:")
    for log_type, data in results.items():
        exists = "✓" if data['count'] > 0 or data.get('path') else "✗"
        print(f"  {exists} {log_type}: {data['path']}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("LOG PARSER - USAGE EXAMPLES")
    print("=" * 70)
    print("\nNOTE: These examples may show no results if log files don't exist")
    print("or if you don't have permissions to read them.\n")
    
    try:
        example_basic_collection()
        example_time_filtering()
        example_keyword_search()
        example_pid_filtering()
        example_security_monitoring()
        example_custom_paths()
        
        print("\n" + "=" * 70)
        print("All examples completed!")
        print("=" * 70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user.")
    except Exception as e:
        print(f"\n\nError running examples: {e}")


if __name__ == "__main__":
    main()
