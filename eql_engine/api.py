"""
FastAPI application for the EQL Engine REST API.

Provides endpoints for:
- Testing EQL queries against event data
- CRUD operations for managing saved rules
- Exporting rules library
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .engine import ExecutionEngine
from .models import ExecutionResult, Match
from .parser import parse_query
from .storage import RulesStorage


# Pydantic models for API requests/responses


class ValidationError(BaseModel):
    """Validation error details."""
    field: str
    message: str


class ValidationState(BaseModel):
    """Validation state for events."""
    is_valid: bool
    errors: List[ValidationError] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class MatchResult(BaseModel):
    """A single match result."""
    events: List[Dict[str, Any]]
    timestamp: str
    group_key: Optional[str] = None


class TestResponse(BaseModel):
    """Response from test endpoint."""
    matches: List[MatchResult]
    total_matches: int
    total_events_processed: int
    execution_time_ms: float
    validation_state: ValidationState
    errors: List[str] = Field(default_factory=list)


class TestRequest(BaseModel):
    """Request to test an EQL query."""
    query: str = Field(..., description="EQL query string")
    events: List[Dict[str, Any]] = Field(..., description="List of event objects")


class RuleCreate(BaseModel):
    """Request to create a new rule."""
    name: str = Field(..., description="Rule name")
    description: str = Field(..., description="Rule description")
    severity: str = Field(..., description="Severity level (low, medium, high, critical)")
    query: str = Field(..., description="EQL query string")


class RuleUpdate(BaseModel):
    """Request to update a rule."""
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    query: Optional[str] = None


class Rule(BaseModel):
    """A saved EQL rule."""
    id: str
    name: str
    description: str
    severity: str
    query: str
    created_at: str
    updated_at: str


class RulesExport(BaseModel):
    """Export of all rules."""
    rules: List[Rule]
    export_timestamp: str
    total_count: int


def validate_events(events: List[Dict[str, Any]]) -> ValidationState:
    """Validate events for required fields and timestamp presence.

    Args:
        events: List of event dictionaries to validate

    Returns:
        ValidationState with validation results
    """
    errors: List[ValidationError] = []
    warnings: List[str] = []

    if not events:
        errors.append(
            ValidationError(
                field="events",
                message="Events list is empty"
            )
        )
        return ValidationState(is_valid=False, errors=errors, warnings=warnings)

    # Check for timestamp presence in at least some events
    timestamp_fields = {"timestamp", "ts", "@timestamp", "time", "datetime"}
    events_with_timestamp = 0

    for i, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(
                ValidationError(
                    field=f"events[{i}]",
                    message="Event must be a dictionary"
                )
            )
            continue

        # Check for timestamp
        has_timestamp = any(field in event for field in timestamp_fields)
        if has_timestamp:
            events_with_timestamp += 1

    if events_with_timestamp == 0:
        warnings.append("No timestamp field detected in any events (looking for: timestamp, ts, @timestamp, time, datetime)")

    # Check for common Wazuh fields
    wazuh_fields = {"agent", "rule", "level", "data", "srcip", "dstip", "action"}
    has_wazuh_like_fields = any(
        any(field in event for field in wazuh_fields)
        for event in events
    )

    if not has_wazuh_like_fields:
        warnings.append("No Wazuh-like fields detected (agent, rule, level, data, srcip, dstip, action)")

    is_valid = len(errors) == 0

    return ValidationState(is_valid=is_valid, errors=errors, warnings=warnings)


def create_app(rules_storage: Optional[RulesStorage] = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        rules_storage: Optional RulesStorage instance (for testing)

    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="EQL Engine API",
        description="REST API for Event Query Language testing and rule management",
        version="1.0.0"
    )

    # Initialize storage
    storage = rules_storage or RulesStorage("eql_engine/rules.json")
    engine = ExecutionEngine()

    # API Routes

    @app.post("/api/test", response_model=TestResponse)
    async def test_query(request: TestRequest) -> TestResponse:
        """Test an EQL query against event data.

        Args:
            request: Test request with query and events

        Returns:
            TestResponse with matches, stats, and validation state
        """
        # Validate events
        validation_state = validate_events(request.events)

        # Parse and execute query
        errors = []
        matches_data = []
        total_matches = 0
        total_events = len(request.events)
        execution_time_ms = 0.0

        try:
            # Parse the query
            query, timerange = parse_query(request.query)

            # Execute the query
            result: ExecutionResult = engine.execute(query, request.events, timerange)

            # Convert matches to response format
            for match in result.matches:
                match_result = MatchResult(
                    events=match.events,
                    timestamp=match.timestamp.isoformat(),
                    group_key=match.group_key
                )
                matches_data.append(match_result)

            total_matches = result.total_matches
            execution_time_ms = result.execution_time_ms
            errors = result.errors

        except Exception as e:
            errors.append(f"Query execution failed: {str(e)}")

        return TestResponse(
            matches=matches_data,
            total_matches=total_matches,
            total_events_processed=total_events,
            execution_time_ms=execution_time_ms,
            validation_state=validation_state,
            errors=errors
        )

    @app.get("/api/rules", response_model=List[Rule])
    async def list_rules() -> List[Rule]:
        """Get all saved rules.

        Returns:
            List of all rules
        """
        rules_data = storage.get_all()
        return [Rule(**rule) for rule in rules_data]

    @app.post("/api/rules", response_model=Rule)
    async def create_rule(request: RuleCreate) -> Rule:
        """Create a new rule.

        Args:
            request: Rule creation request

        Returns:
            Created rule with ID and timestamps
        """
        # Validate query syntax
        try:
            parse_query(request.query)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid EQL query: {str(e)}"
            )

        # Create rule with generated ID
        rule_data = {
            "id": str(uuid.uuid4()),
            "name": request.name,
            "description": request.description,
            "severity": request.severity,
            "query": request.query,
        }

        created_rule = storage.create(rule_data)
        return Rule(**created_rule)

    @app.get("/api/rules/{rule_id}", response_model=Rule)
    async def get_rule(rule_id: str) -> Rule:
        """Get a rule by ID.

        Args:
            rule_id: The rule ID

        Returns:
            The rule

        Raises:
            HTTPException: If rule not found
        """
        rule = storage.get_by_id(rule_id)
        if rule is None:
            raise HTTPException(
                status_code=404,
                detail=f"Rule '{rule_id}' not found"
            )
        return Rule(**rule)

    @app.put("/api/rules/{rule_id}", response_model=Rule)
    async def update_rule(rule_id: str, request: RuleUpdate) -> Rule:
        """Update a rule.

        Args:
            rule_id: The rule ID
            request: Update request with fields to modify

        Returns:
            Updated rule

        Raises:
            HTTPException: If rule not found or invalid query
        """
        # Get existing rule
        existing_rule = storage.get_by_id(rule_id)
        if existing_rule is None:
            raise HTTPException(
                status_code=404,
                detail=f"Rule '{rule_id}' not found"
            )

        # Validate new query if provided
        if request.query is not None:
            try:
                parse_query(request.query)
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid EQL query: {str(e)}"
                )

        # Build updates dict (only include non-None fields)
        updates = {}
        if request.name is not None:
            updates["name"] = request.name
        if request.description is not None:
            updates["description"] = request.description
        if request.severity is not None:
            updates["severity"] = request.severity
        if request.query is not None:
            updates["query"] = request.query

        updated_rule = storage.update(rule_id, updates)
        if updated_rule is None:
            raise HTTPException(
                status_code=404,
                detail=f"Rule '{rule_id}' not found"
            )

        return Rule(**updated_rule)

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule(rule_id: str) -> Dict[str, str]:
        """Delete a rule.

        Args:
            rule_id: The rule ID

        Returns:
            Confirmation message

        Raises:
            HTTPException: If rule not found
        """
        if not storage.delete(rule_id):
            raise HTTPException(
                status_code=404,
                detail=f"Rule '{rule_id}' not found"
            )

        return {"message": f"Rule '{rule_id}' deleted successfully"}

    @app.get("/api/rules/export/download", response_model=RulesExport)
    async def export_rules(format: str = Query("json", pattern="^(json|ndjson)$")) -> RulesExport:
        """Export all rules.

        Args:
            format: Export format (json or ndjson)

        Returns:
            RulesExport with all rules and metadata
        """
        rules_data = storage.get_all()
        rules = [Rule(**rule) for rule in rules_data]

        return RulesExport(
            rules=rules,
            export_timestamp=datetime.now(timezone.utc).isoformat(),
            total_count=len(rules)
        )

    @app.get("/health")
    async def health_check() -> Dict[str, str]:
        """Health check endpoint.

        Returns:
            Health status
        """
        return {"status": "healthy"}

    return app


# Create the app instance
app = create_app()
