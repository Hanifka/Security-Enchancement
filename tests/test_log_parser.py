"""
Unit tests for log_parser module.

Tests parsing, filtering, and aggregation functionality with fixture log snippets.
"""

import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from agent_service.log_parser import (
    AuditLogParser,
    LogEntry,
    SyslogParser,
    YumLogParser,
    collect_logs,
    get_log_paths,
)


# Test fixtures - sample log data
AUDIT_LOG_FIXTURE = """type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55f8a9b7e010 a1=55f8a9b7f3e0 a2=55f8a9b7e860 a3=7ffc2e9c8de0 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" key="audit-wazuh-c"
type=EXECVE msg=audit(1700000100.456:457): argc=2 a0="ls" a1="-la"
type=PATH msg=audit(1700000200.789:458): item=0 name="/etc/passwd" inode=12345 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=SYSCALL msg=audit(1700000300.111:459): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd12345678 a2=0 a3=0 items=1 ppid=2000 pid=2001 auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts1 ses=5 comm="cat" exe="/usr/bin/cat" key="passwd_access"
"""

SYSLOG_FIXTURE = """Jan 15 10:30:45 myhost sshd[1234]: Accepted publickey for user1 from 192.168.1.100 port 54321 ssh2: RSA SHA256:abcd1234
Jan 15 10:31:12 myhost systemd[1]: Started Session 123 of user user1.
Jan 15 10:32:00 myhost kernel: [12345.678901] TCP: request_sock_TCP: Possible SYN flooding on port 80.
Jan 15 10:33:45 myhost sudo[5678]: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/ls -la /root
Jan 15 10:34:00 myhost cron[9999]: (root) CMD (/usr/local/bin/backup.sh)
"""

AUTH_LOG_FIXTURE = """Jan 15 11:00:01 webserver sshd[10001]: Failed password for invalid user admin from 10.0.0.50 port 22222 ssh2
Jan 15 11:00:15 webserver sshd[10002]: Accepted password for devuser from 10.0.0.100 port 33333 ssh2
Jan 15 11:01:00 webserver sudo[10100]: devuser : TTY=pts/0 ; PWD=/home/devuser ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Jan 15 11:02:30 webserver systemd-logind[500]: New session 42 of user devuser.
"""

YUM_LOG_FIXTURE = """Jan 10 08:15:32 Installed: httpd-2.4.6-97.el7.x86_64
Jan 10 08:15:45 Installed: mod_ssl-1:2.4.6-97.el7.x86_64
Jan 11 14:20:10 Updated: kernel-3.10.0-1160.el7.x86_64
Jan 12 09:30:00 Erased: old-package-1.0-1.el7.x86_64
Jan 13 16:45:22 Installed: python3-pip-9.0.3-8.el7.noarch
"""

ISO_SYSLOG_FIXTURE = """2024-01-15T10:30:45.123456+00:00 server1 nginx[8080]: 192.168.1.1 - - [15/Jan/2024:10:30:45 +0000] "GET /api/health HTTP/1.1" 200 15
2024-01-15T10:31:00.654321+00:00 server1 postgresql[5432]: LOG: checkpoint complete: wrote 250 buffers
"""


class TestAuditLogParser:
    """Test cases for audit log parsing."""
    
    def test_parse_syscall_entry(self):
        """Test parsing a SYSCALL audit entry."""
        parser = AuditLogParser("/var/log/audit/audit.log")
        line = 'type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 comm="bash" exe="/usr/bin/bash"'
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.timestamp == datetime.fromtimestamp(1700000000.123)
        assert entry.pid == 5678
        assert entry.process == "bash"
        assert "syscall=59" in entry.message
        assert entry.metadata['type'] == 'SYSCALL'
        assert entry.metadata['serial'] == '456'
    
    def test_parse_path_entry(self):
        """Test parsing a PATH audit entry."""
        parser = AuditLogParser("/var/log/audit/audit.log")
        line = 'type=PATH msg=audit(1700000200.789:458): item=0 name="/etc/passwd" inode=12345'
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.timestamp == datetime.fromtimestamp(1700000200.789)
        assert '/etc/passwd' in entry.message
        assert entry.metadata['type'] == 'PATH'
    
    def test_parse_invalid_line(self):
        """Test parsing an invalid audit line."""
        parser = AuditLogParser("/var/log/audit/audit.log")
        line = "This is not a valid audit log line"
        
        entry = parser.parse_line(line)
        
        assert entry is None
    
    def test_parse_file_with_fixture(self, tmp_path):
        """Test parsing a complete audit log file."""
        log_file = tmp_path / "audit.log"
        log_file.write_text(AUDIT_LOG_FIXTURE)
        
        parser = AuditLogParser(str(log_file))
        entries = parser.parse_file()
        
        assert len(entries) == 4
        assert entries[0].process == "bash"
        assert entries[0].pid == 5678
        assert entries[3].process == "cat"
        assert entries[3].pid == 2001


class TestSyslogParser:
    """Test cases for syslog and auth.log parsing."""
    
    def test_parse_syslog_with_pid(self):
        """Test parsing a syslog entry with PID."""
        parser = SyslogParser("/var/log/syslog")
        line = "Jan 15 10:30:45 myhost sshd[1234]: Accepted publickey for user1"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.host == "myhost"
        assert entry.process == "sshd"
        assert entry.pid == 1234
        assert "Accepted publickey" in entry.message
    
    def test_parse_syslog_without_pid(self):
        """Test parsing a syslog entry without PID."""
        parser = SyslogParser("/var/log/syslog")
        line = "Jan 15 10:31:12 myhost systemd: Started Session 123"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.host == "myhost"
        assert entry.process == "systemd"
        assert entry.pid is None
        assert "Started Session" in entry.message
    
    def test_parse_iso_format_syslog(self):
        """Test parsing ISO format syslog entries."""
        parser = SyslogParser("/var/log/syslog")
        line = "2024-01-15T10:30:45.123456+00:00 server1 nginx[8080]: test message"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.host == "server1"
        assert entry.process == "nginx"
        assert entry.pid == 8080
        assert entry.timestamp.year == 2024
    
    def test_parse_file_with_fixture(self, tmp_path):
        """Test parsing a complete syslog file."""
        log_file = tmp_path / "syslog"
        log_file.write_text(SYSLOG_FIXTURE)
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file()
        
        assert len(entries) == 5
        assert entries[0].process == "sshd"
        assert entries[0].pid == 1234
        assert entries[3].process == "sudo"
        assert entries[3].pid == 5678


class TestYumLogParser:
    """Test cases for yum log parsing."""
    
    def test_parse_installed_entry(self):
        """Test parsing a yum install entry."""
        parser = YumLogParser("/var/log/yum.log")
        line = "Jan 10 08:15:32 Installed: httpd-2.4.6-97.el7.x86_64"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.process == "yum"
        assert entry.metadata['action'] == "Installed"
        assert "httpd-2.4.6" in entry.message
    
    def test_parse_updated_entry(self):
        """Test parsing a yum update entry."""
        parser = YumLogParser("/var/log/yum.log")
        line = "Jan 11 14:20:10 Updated: kernel-3.10.0-1160.el7.x86_64"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.metadata['action'] == "Updated"
        assert "kernel-3.10.0" in entry.message
    
    def test_parse_file_with_fixture(self, tmp_path):
        """Test parsing a complete yum log file."""
        log_file = tmp_path / "yum.log"
        log_file.write_text(YUM_LOG_FIXTURE)
        
        parser = YumLogParser(str(log_file))
        entries = parser.parse_file()
        
        assert len(entries) == 5
        assert entries[0].metadata['action'] == "Installed"
        assert entries[2].metadata['action'] == "Updated"
        assert entries[3].metadata['action'] == "Erased"


class TestFiltering:
    """Test cases for log filtering functionality."""
    
    def test_timestamp_filtering(self, tmp_path):
        """Test filtering by timestamp range."""
        log_file = tmp_path / "syslog"
        log_file.write_text(SYSLOG_FIXTURE)
        
        parser = SyslogParser(str(log_file))
        
        # Create timestamp range for Jan 15, 10:31 - 10:33
        current_year = datetime.now().year
        start_time = datetime(current_year, 1, 15, 10, 31, 0)
        end_time = datetime(current_year, 1, 15, 10, 33, 0)
        
        entries = parser.parse_file(start_time=start_time, end_time=end_time)
        
        # Should only get entries within the time range
        assert len(entries) == 2
        assert entries[0].process == "systemd"
        assert entries[1].process == "kernel"
    
    def test_keyword_filtering(self, tmp_path):
        """Test filtering by keywords."""
        log_file = tmp_path / "auth.log"
        log_file.write_text(AUTH_LOG_FIXTURE)
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file(keywords=["sudo"])
        
        assert len(entries) == 1
        assert entries[0].process == "sudo"
    
    def test_multiple_keyword_filtering(self, tmp_path):
        """Test filtering with multiple keywords (OR logic)."""
        log_file = tmp_path / "auth.log"
        log_file.write_text(AUTH_LOG_FIXTURE)
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file(keywords=["Failed", "sudo"])
        
        assert len(entries) == 2
        assert any("Failed password" in e.message for e in entries)
        assert any(e.process == "sudo" for e in entries)
    
    def test_pid_filtering(self, tmp_path):
        """Test filtering by process IDs."""
        log_file = tmp_path / "syslog"
        log_file.write_text(SYSLOG_FIXTURE)
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file(pids=[1234, 5678])
        
        assert len(entries) == 2
        assert all(e.pid in [1234, 5678] for e in entries)
    
    def test_max_entries_limit(self, tmp_path):
        """Test limiting maximum number of entries."""
        log_file = tmp_path / "syslog"
        log_file.write_text(SYSLOG_FIXTURE)
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file(max_entries=2)
        
        assert len(entries) == 2
    
    def test_combined_filters(self, tmp_path):
        """Test combining multiple filters."""
        log_file = tmp_path / "audit.log"
        log_file.write_text(AUDIT_LOG_FIXTURE)
        
        parser = AuditLogParser(str(log_file))
        
        start_time = datetime.fromtimestamp(1700000100)
        end_time = datetime.fromtimestamp(1700000250)
        
        entries = parser.parse_file(
            start_time=start_time,
            end_time=end_time,
            keywords=["passwd"]
        )
        
        assert len(entries) == 1
        assert "/etc/passwd" in entries[0].message


class TestCollectLogs:
    """Test cases for the collect_logs function."""
    
    def test_collect_logs_basic(self, tmp_path):
        """Test basic log collection from multiple sources."""
        # Create test log files
        audit_log = tmp_path / "audit.log"
        audit_log.write_text(AUDIT_LOG_FIXTURE)
        
        syslog = tmp_path / "syslog"
        syslog.write_text(SYSLOG_FIXTURE)
        
        yum_log = tmp_path / "yum.log"
        yum_log.write_text(YUM_LOG_FIXTURE)
        
        log_paths = {
            'audit': str(audit_log),
            'syslog': str(syslog),
            'yum': str(yum_log),
        }
        
        results = collect_logs(log_paths=log_paths)
        
        assert 'audit' in results
        assert 'syslog' in results
        assert 'yum' in results
        
        assert results['audit']['count'] == 4
        assert results['syslog']['count'] == 5
        assert results['yum']['count'] == 5
    
    def test_collect_logs_with_filters(self, tmp_path):
        """Test log collection with filtering."""
        syslog = tmp_path / "syslog"
        syslog.write_text(SYSLOG_FIXTURE)
        
        log_paths = {
            'syslog': str(syslog),
        }
        
        results = collect_logs(
            keywords=["ssh", "sudo"],
            log_paths=log_paths
        )
        
        assert results['syslog']['count'] == 2
        entries = results['syslog']['entries']
        assert any(e.process == "sshd" for e in entries)
        assert any(e.process == "sudo" for e in entries)
    
    def test_collect_logs_missing_files(self, tmp_path):
        """Test that missing log files are gracefully skipped."""
        log_paths = {
            'audit': '/nonexistent/audit.log',
            'syslog': '/nonexistent/syslog',
        }
        
        results = collect_logs(log_paths=log_paths)
        
        # Should return empty results, not crash
        assert isinstance(results, dict)
        assert all(v['count'] == 0 for v in results.values())
    
    def test_collect_logs_max_entries(self, tmp_path):
        """Test max_entries limit per source."""
        syslog = tmp_path / "syslog"
        syslog.write_text(SYSLOG_FIXTURE)
        
        log_paths = {
            'syslog': str(syslog),
        }
        
        results = collect_logs(max_entries=2, log_paths=log_paths)
        
        assert results['syslog']['count'] == 2
        assert len(results['syslog']['entries']) == 2
    
    def test_collect_logs_per_source_aggregation(self, tmp_path):
        """Test that results are properly aggregated per source."""
        audit_log = tmp_path / "audit.log"
        audit_log.write_text(AUDIT_LOG_FIXTURE)
        
        syslog = tmp_path / "syslog"
        syslog.write_text(SYSLOG_FIXTURE)
        
        log_paths = {
            'audit': str(audit_log),
            'syslog': str(syslog),
        }
        
        results = collect_logs(log_paths=log_paths)
        
        # Verify structure
        for log_type, data in results.items():
            assert 'count' in data
            assert 'entries' in data
            assert 'path' in data
            assert isinstance(data['count'], int)
            assert isinstance(data['entries'], list)
            assert isinstance(data['path'], str)
            
            # Verify all entries have correct source
            for entry in data['entries']:
                assert isinstance(entry, LogEntry)


class TestLogPathConfiguration:
    """Test cases for log path configuration."""
    
    def test_default_log_paths(self):
        """Test that default paths are returned."""
        paths = get_log_paths()
        
        assert 'audit' in paths
        assert 'syslog' in paths
        assert 'auth' in paths
        assert 'yum' in paths
        
        assert paths['audit'] == '/var/log/audit/audit.log'
        assert paths['syslog'] == '/var/log/syslog'
    
    def test_config_dict_override(self):
        """Test that config dict overrides defaults."""
        config = {
            'audit': '/custom/audit.log',
            'syslog': '/custom/syslog',
        }
        
        paths = get_log_paths(config)
        
        assert paths['audit'] == '/custom/audit.log'
        assert paths['syslog'] == '/custom/syslog'
        assert paths['auth'] == '/var/log/auth.log'  # Default preserved
    
    def test_env_var_override(self, monkeypatch):
        """Test that environment variables override defaults."""
        monkeypatch.setenv('LOG_PATH_AUDIT', '/env/audit.log')
        monkeypatch.setenv('LOG_PATH_SYSLOG', '/env/syslog')
        
        paths = get_log_paths()
        
        assert paths['audit'] == '/env/audit.log'
        assert paths['syslog'] == '/env/syslog'
        assert paths['auth'] == '/var/log/auth.log'  # Default preserved
    
    def test_config_dict_overrides_env_var(self, monkeypatch):
        """Test that config dict takes priority over env vars."""
        monkeypatch.setenv('LOG_PATH_AUDIT', '/env/audit.log')
        
        config = {
            'audit': '/config/audit.log',
        }
        
        paths = get_log_paths(config)
        
        assert paths['audit'] == '/config/audit.log'
    
    def test_graceful_permission_denied(self, tmp_path):
        """Test graceful handling of permission denied errors."""
        # Create a file with no read permissions
        log_file = tmp_path / "restricted.log"
        log_file.write_text(SYSLOG_FIXTURE)
        log_file.chmod(0o000)
        
        try:
            parser = SyslogParser(str(log_file))
            entries = parser.parse_file()
            
            # Should return empty list, not crash
            assert entries == []
        finally:
            # Restore permissions for cleanup
            log_file.chmod(0o644)


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_log_file(self, tmp_path):
        """Test parsing an empty log file."""
        log_file = tmp_path / "empty.log"
        log_file.write_text("")
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file()
        
        assert entries == []
    
    def test_malformed_lines_skipped(self, tmp_path):
        """Test that malformed lines are skipped."""
        log_file = tmp_path / "malformed.log"
        log_file.write_text("""
Jan 15 10:30:45 myhost sshd[1234]: Valid log entry
This is not a valid log line
Another invalid line without proper format
Jan 15 10:31:00 myhost kernel: Another valid entry
        """)
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file()
        
        assert len(entries) == 2
        assert entries[0].process == "sshd"
        assert entries[1].process == "kernel"
    
    def test_unicode_handling(self, tmp_path):
        """Test handling of unicode characters in logs."""
        log_file = tmp_path / "unicode.log"
        log_file.write_text("Jan 15 10:30:45 myhost app[1234]: User 'José' logged in 你好\n")
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file()
        
        assert len(entries) == 1
        assert "José" in entries[0].message
    
    def test_very_long_lines(self, tmp_path):
        """Test handling of very long log lines."""
        long_message = "A" * 10000
        log_file = tmp_path / "long.log"
        log_file.write_text(f"Jan 15 10:30:45 myhost app[1234]: {long_message}\n")
        
        parser = SyslogParser(str(log_file))
        entries = parser.parse_file()
        
        assert len(entries) == 1
        assert len(entries[0].message) == 10000
