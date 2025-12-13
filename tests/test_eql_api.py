"""
Tests for the EQL Engine FastAPI application.

Tests API endpoints for query testing, rule CRUD operations, and event validation.
Uses TestClient with mocked storage for isolated unit testing.
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from eql_engine.api import create_app, ValidationError, ValidationState
from eql_engine.storage import RulesStorage


@pytest.fixture
def temp_rules_file():
    """Create a temporary rules file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump([], f)
        temp_path = f.name
    yield temp_path
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def storage(temp_rules_file):
    """Create a RulesStorage instance with temporary file."""
    return RulesStorage(temp_rules_file)


@pytest.fixture
def client(storage):
    """Create a test client with mocked storage."""
    app = create_app(rules_storage=storage)
    return TestClient(app)


class TestEventValidation:
    """Tests for event validation logic."""

    def test_validate_empty_events(self):
        """Test validation of empty events list."""
        from eql_engine.api import validate_events

        validation = validate_events([])
        assert not validation.is_valid
        assert len(validation.errors) > 0

    def test_validate_events_with_timestamp(self):
        """Test validation of events with timestamp."""
        from eql_engine.api import validate_events

        events = [
            {"event_code": 1, "timestamp": datetime.now()},
            {"event_code": 2, "timestamp": datetime.now()},
        ]
        validation = validate_events(events)
        assert validation.is_valid
        assert len(validation.errors) == 0

    def test_validate_events_with_ts_field(self):
        """Test validation with ts field."""
        from eql_engine.api import validate_events

        events = [
            {"event_code": 1, "ts": datetime.now()},
        ]
        validation = validate_events(events)
        assert validation.is_valid

    def test_validate_events_with_at_timestamp_field(self):
        """Test validation with @timestamp field."""
        from eql_engine.api import validate_events

        events = [
            {"event_code": 1, "@timestamp": datetime.now()},
        ]
        validation = validate_events(events)
        assert validation.is_valid

    def test_validate_events_missing_timestamp(self):
        """Test validation warns when timestamp is missing."""
        from eql_engine.api import validate_events

        events = [
            {"event_code": 1},
        ]
        validation = validate_events(events)
        assert validation.is_valid
        assert len(validation.warnings) > 0
        assert "timestamp" in validation.warnings[0].lower()

    def test_validate_events_missing_wazuh_fields(self):
        """Test validation warns when Wazuh fields are missing."""
        from eql_engine.api import validate_events

        events = [
            {"event_code": 1, "timestamp": datetime.now()},
        ]
        validation = validate_events(events)
        assert validation.is_valid
        assert any("wazuh" in w.lower() for w in validation.warnings)

    def test_validate_events_with_wazuh_fields(self):
        """Test validation with Wazuh-like fields."""
        from eql_engine.api import validate_events

        events = [
            {"timestamp": datetime.now(), "agent": "agent-001", "rule": "1001"},
        ]
        validation = validate_events(events)
        assert validation.is_valid
        assert not any("wazuh" in w.lower() for w in validation.warnings)

    def test_validate_events_invalid_event_type(self):
        """Test validation catches non-dict events."""
        from eql_engine.api import validate_events

        events = [
            "not a dict",
        ]
        validation = validate_events(events)
        assert not validation.is_valid
        assert len(validation.errors) > 0


class TestTestEndpoint:
    """Tests for the /api/test endpoint."""

    def test_test_simple_filter(self, client):
        """Test simple filter query."""
        events = [
            {"process_name": "cmd.exe", "timestamp": datetime.now().isoformat()},
            {"process_name": "notepad.exe", "timestamp": datetime.now().isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": 'filter(process_name == "cmd.exe")',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert data["total_matches"] == 1
        assert data["total_events_processed"] == 2
        assert data["validation_state"]["is_valid"]

    def test_test_filter_with_multiple_predicates(self, client):
        """Test filter with multiple predicates."""
        base_time = datetime.now()
        events = [
            {"process_name": "cmd.exe", "process_pid": 100, "timestamp": base_time.isoformat()},
            {"process_name": "cmd.exe", "process_pid": 200, "timestamp": base_time.isoformat()},
            {"process_name": "powershell.exe", "process_pid": 100, "timestamp": base_time.isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": 'filter(process_name == "cmd.exe" and process_pid == 100)',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert data["total_matches"] == 1

    def test_test_filter_with_regex(self, client):
        """Test filter with regex pattern."""
        events = [
            {"process_name": "cmd.exe", "timestamp": datetime.now().isoformat()},
            {"process_name": "powershell.exe", "timestamp": datetime.now().isoformat()},
            {"process_name": "notepad.exe", "timestamp": datetime.now().isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": r'filter(process_name == /.*\.exe/)',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert data["total_matches"] == 3

    def test_test_sequence_query(self, client):
        """Test sequence query."""
        base_time = datetime.now()
        events = [
            {"event_type": "login", "user": "admin", "timestamp": base_time.isoformat()},
            {"event_type": "command", "user": "admin", "timestamp": (base_time + timedelta(seconds=5)).isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": 'sequence[filter(event_type == "login"), filter(event_type == "command")]',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert data["total_matches"] >= 1

    def test_test_threshold_query(self, client):
        """Test threshold query."""
        events = [
            {"event_code": 4625, "timestamp": datetime.now().isoformat()},
            {"event_code": 4625, "timestamp": datetime.now().isoformat()},
            {"event_code": 4625, "timestamp": datetime.now().isoformat()},
            {"event_code": 4625, "timestamp": datetime.now().isoformat()},
            {"event_code": 4625, "timestamp": datetime.now().isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": 'threshold(filter(event_code == 4625), min_count = 3)',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert data["total_matches"] >= 1

    def test_test_invalid_query(self, client):
        """Test with invalid EQL query."""
        events = [
            {"timestamp": datetime.now().isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": "invalid query syntax",
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert len(data["errors"]) > 0

    def test_test_empty_events(self, client):
        """Test with empty events list."""
        response = client.post("/api/test", json={
            "query": 'filter(process.name == "cmd.exe")',
            "events": []
        })
        assert response.status_code == 200
        data = response.json()
        assert not data["validation_state"]["is_valid"]

    def test_test_validation_state_warning(self, client):
        """Test validation state includes warnings for missing fields."""
        events = [
            {"event_code": 1},  # No timestamp
        ]
        response = client.post("/api/test", json={
            "query": 'filter(event_code == 1)',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert len(data["validation_state"]["warnings"]) > 0

    def test_test_with_timerange(self, client):
        """Test query with timerange constraint."""
        base_time = datetime.now()
        events = [
            {"event_code": 1, "timestamp": base_time.isoformat()},
            {"event_code": 1, "timestamp": (base_time + timedelta(seconds=3)).isoformat()},
            {"event_code": 1, "timestamp": (base_time + timedelta(seconds=10)).isoformat()},
        ]
        response = client.post("/api/test", json={
            "query": 'filter(event_code == 1) | timerange 5s',
            "events": events
        })
        assert response.status_code == 200
        data = response.json()
        assert data["total_events_processed"] == 3


class TestRulesCrud:
    """Tests for rules CRUD endpoints."""

    def test_get_rules_empty(self, client):
        """Test getting rules when empty."""
        response = client.get("/api/rules")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_create_rule(self, client):
        """Test creating a rule."""
        response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Rule"
        assert data["description"] == "A test rule"
        assert data["severity"] == "high"
        assert data["query"] == 'filter(process.name == "cmd.exe")'
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_rule_invalid_query(self, client):
        """Test creating rule with invalid query."""
        response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": "invalid query syntax"
        })
        assert response.status_code == 400

    def test_get_rules_after_create(self, client):
        """Test getting rules after creation."""
        # Create a rule
        create_response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        rule_id = create_response.json()["id"]

        # Get all rules
        response = client.get("/api/rules")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == rule_id

    def test_get_rule_by_id(self, client):
        """Test getting a rule by ID."""
        # Create a rule
        create_response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        rule_id = create_response.json()["id"]

        # Get the rule
        response = client.get(f"/api/rules/{rule_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == rule_id
        assert data["name"] == "Test Rule"

    def test_get_rule_not_found(self, client):
        """Test getting non-existent rule."""
        response = client.get("/api/rules/nonexistent-id")
        assert response.status_code == 404

    def test_update_rule(self, client):
        """Test updating a rule."""
        # Create a rule
        create_response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        rule_id = create_response.json()["id"]

        # Update the rule
        response = client.put(f"/api/rules/{rule_id}", json={
            "name": "Updated Rule",
            "severity": "critical"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Rule"
        assert data["severity"] == "critical"
        assert data["description"] == "A test rule"  # Unchanged

    def test_update_rule_invalid_query(self, client):
        """Test updating rule with invalid query."""
        # Create a rule
        create_response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        rule_id = create_response.json()["id"]

        # Try to update with invalid query
        response = client.put(f"/api/rules/{rule_id}", json={
            "query": "invalid query"
        })
        assert response.status_code == 400

    def test_update_nonexistent_rule(self, client):
        """Test updating non-existent rule."""
        response = client.put("/api/rules/nonexistent-id", json={
            "name": "Updated Name"
        })
        assert response.status_code == 404

    def test_delete_rule(self, client):
        """Test deleting a rule."""
        # Create a rule
        create_response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        rule_id = create_response.json()["id"]

        # Delete the rule
        response = client.delete(f"/api/rules/{rule_id}")
        assert response.status_code == 200
        data = response.json()
        assert "deleted" in data["message"]

        # Verify it's deleted
        get_response = client.get(f"/api/rules/{rule_id}")
        assert get_response.status_code == 404

    def test_delete_nonexistent_rule(self, client):
        """Test deleting non-existent rule."""
        response = client.delete("/api/rules/nonexistent-id")
        assert response.status_code == 404

    def test_timestamps_created_at_unchanged(self, client):
        """Test that created_at doesn't change on update."""
        # Create a rule
        create_response = client.post("/api/rules", json={
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "query": 'filter(process.name == "cmd.exe")'
        })
        rule_data = create_response.json()
        rule_id = rule_data["id"]
        original_created_at = rule_data["created_at"]

        # Update the rule
        client.put(f"/api/rules/{rule_id}", json={
            "name": "Updated Rule"
        })

        # Get the rule
        response = client.get(f"/api/rules/{rule_id}")
        data = response.json()
        assert data["created_at"] == original_created_at


class TestExportEndpoint:
    """Tests for the export endpoint."""

    def test_export_empty(self, client):
        """Test exporting when no rules exist."""
        response = client.get("/api/rules/export/download")
        assert response.status_code == 200
        data = response.json()
        assert data["rules"] == []
        assert data["total_count"] == 0
        assert "export_timestamp" in data

    def test_export_with_rules(self, client):
        """Test exporting with multiple rules."""
        # Create rules
        client.post("/api/rules", json={
            "name": "Rule 1",
            "description": "First rule",
            "severity": "high",
            "query": 'filter(event_code == 1)'
        })
        client.post("/api/rules", json={
            "name": "Rule 2",
            "description": "Second rule",
            "severity": "low",
            "query": 'filter(event_code == 2)'
        })

        # Export
        response = client.get("/api/rules/export/download")
        assert response.status_code == 200
        data = response.json()
        assert len(data["rules"]) == 2
        assert data["total_count"] == 2
        assert data["rules"][0]["name"] == "Rule 1"
        assert data["rules"][1]["name"] == "Rule 2"


class TestHealthCheck:
    """Tests for health check endpoint."""

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestStoragePersistence:
    """Tests for storage persistence."""

    def test_storage_creates_file_if_missing(self, temp_rules_file):
        """Test storage creates file if missing."""
        non_existent_path = Path(temp_rules_file).parent / "new_rules.json"
        non_existent_path.unlink(missing_ok=True)

        storage = RulesStorage(non_existent_path)
        assert non_existent_path.exists()
        assert storage.get_all() == []

    def test_storage_persists_data(self, temp_rules_file):
        """Test that storage persists data across instances."""
        # Create and add rule with first instance
        storage1 = RulesStorage(temp_rules_file)
        rule_data = {
            "id": "test-1",
            "name": "Test Rule",
            "description": "Test",
            "severity": "high",
            "query": 'filter(x == 1)'
        }
        created = storage1.create(rule_data)

        # Read with second instance
        storage2 = RulesStorage(temp_rules_file)
        retrieved = storage2.get_by_id("test-1")
        assert retrieved is not None
        assert retrieved["name"] == "Test Rule"

    def test_storage_thread_safe_operations(self, temp_rules_file):
        """Test that storage is thread-safe."""
        import threading

        storage = RulesStorage(temp_rules_file)
        results = []

        def create_rule(idx):
            rule = {
                "id": f"rule-{idx}",
                "name": f"Rule {idx}",
                "description": f"Rule {idx}",
                "severity": "high",
                "query": 'filter(x == 1)'
            }
            storage.create(rule)
            results.append(idx)

        threads = [threading.Thread(target=create_rule, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        all_rules = storage.get_all()
        assert len(all_rules) == 5


class TestRuleValidation:
    """Tests for rule validation during API operations."""

    def test_create_rule_validates_query(self, client):
        """Test that rule creation validates the query."""
        response = client.post("/api/rules", json={
            "name": "Bad Rule",
            "description": "This has a bad query",
            "severity": "high",
            "query": "filter(this is not valid eql syntax"
        })
        assert response.status_code == 400

    def test_create_rule_accepts_all_query_types(self, client):
        """Test that rule creation accepts all query types."""
        # Filter
        response = client.post("/api/rules", json={
            "name": "Filter Rule",
            "description": "Filter",
            "severity": "high",
            "query": 'filter(event_code == 1)'
        })
        assert response.status_code == 200

        # Sequence
        response = client.post("/api/rules", json={
            "name": "Sequence Rule",
            "description": "Sequence",
            "severity": "high",
            "query": 'sequence[filter(event_code == 1), filter(event_code == 2)]'
        })
        assert response.status_code == 200

        # Threshold
        response = client.post("/api/rules", json={
            "name": "Threshold Rule",
            "description": "Threshold",
            "severity": "high",
            "query": 'threshold(filter(event_code == 1), min_count = 5)'
        })
        assert response.status_code == 200

    def test_rule_with_complex_query(self, client):
        """Test rule with complex query including timerange and by clause."""
        response = client.post("/api/rules", json={
            "name": "Complex Rule",
            "description": "Complex query",
            "severity": "critical",
            "query": 'threshold(filter(event_code == 4625), min_count = 5) | timerange 5m'
        })
        assert response.status_code == 200
        data = response.json()
        assert 'timerange' in data["query"]
