#!/usr/bin/env python3
"""
FastAPI server for the security monitoring dashboard.
Provides API endpoints for agent management and payload execution.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from agent_service import collect_logs, LogEntry


class PayloadRequest(BaseModel):
    """Request model for payload execution."""
    agent_id: str
    command: str
    description: Optional[str] = None


class PayloadExecution(BaseModel):
    """Model for payload execution results."""
    id: str
    agent_id: str
    command: str
    description: Optional[str]
    timestamp: datetime
    status: str  # "running", "completed", "failed"
    duration_ms: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    log_results: Optional[Dict[str, Any]] = None


# In-memory storage for demonstration
# In production, this would be a database
agents_db = [
    {"id": "agent-001", "name": "Security Monitor Alpha", "status": "online", "last_seen": "2024-01-15T10:30:00Z"},
    {"id": "agent-002", "name": "Security Monitor Beta", "status": "online", "last_seen": "2024-01-15T10:29:45Z"},
    {"id": "agent-003", "name": "Security Monitor Gamma", "status": "offline", "last_seen": "2024-01-15T09:15:00Z"},
]

payloads_db: List[PayloadExecution] = []


app = FastAPI(
    title="Security Monitoring Dashboard",
    description="Dashboard for managing security monitoring agents and payloads",
    version="1.0.0"
)


def execute_command_simulation(command: str) -> tuple[str, str, int]:
    """
    Simulate command execution for demonstration purposes.
    In production, this would actually execute commands on the agent.
    """
    import subprocess
    import time
    
    start_time = time.time()
    
    try:
        # For demo purposes, we'll execute some safe commands
        # In production, this would be executed on the remote agent
        if command.strip().startswith("ls"):
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        elif command.strip().startswith("whoami"):
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        elif command.strip().startswith("date"):
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        elif command.strip().startswith("ps"):
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        else:
            # For other commands, return a simulation
            result = subprocess.run(['echo', f'Simulated execution of: {command}'], capture_output=True, text=True)
        
        duration = int((time.time() - start_time) * 1000)
        return result.stdout, result.stderr, duration
        
    except subprocess.TimeoutExpired:
        return "", "Command execution timed out", 30000
    except Exception as e:
        return "", f"Error executing command: {str(e)}", 0


async def execute_payload_async(payload_id: str, agent_id: str, command: str, description: Optional[str]):
    """
    Background task to execute a payload and update its status.
    """
    try:
        # Update status to running
        for payload in payloads_db:
            if payload.id == payload_id:
                payload.status = "running"
                break
        
        # Execute the command
        stdout, stderr, duration = execute_command_simulation(command)
        
        # Collect log data
        log_results = collect_logs(max_entries=100)
        
        # Format log results for the UI
        formatted_results = {}
        for log_type, data in log_results.items():
            formatted_results[log_type.upper()] = {
                "count": data['count'],
                "path": data['path'],
                "entries": [
                    {
                        "timestamp": entry.timestamp.isoformat(),
                        "host": entry.host,
                        "process": entry.process,
                        "pid": entry.pid,
                        "message": entry.message,
                        "raw_line": entry.raw_line,
                        "metadata": entry.metadata
                    }
                    for entry in data['entries']
                ]
            }
        
        # Update payload with results
        for payload in payloads_db:
            if payload.id == payload_id:
                payload.status = "completed"
                payload.duration_ms = duration
                payload.stdout = stdout
                payload.stderr = stderr
                payload.log_results = formatted_results
                break
                
    except Exception as e:
        # Update payload with error
        for payload in payloads_db:
            if payload.id == payload_id:
                payload.status = "failed"
                payload.stderr = f"Execution failed: {str(e)}"
                break


@app.get("/api/agents")
async def get_agents():
    """Get list of available agents."""
    return {"agents": agents_db}


@app.get("/api/payloads")
async def get_payloads():
    """Get payload execution history."""
    return {"payloads": payloads_db}


@app.post("/api/payloads")
async def create_payload(request: PayloadRequest, background_tasks: BackgroundTasks):
    """Create and execute a new payload."""
    # Validate agent exists
    agent_exists = any(agent["id"] == request.agent_id for agent in agents_db)
    if not agent_exists:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Create new payload
    payload_id = str(uuid.uuid4())
    payload = PayloadExecution(
        id=payload_id,
        agent_id=request.agent_id,
        command=request.command,
        description=request.description,
        timestamp=datetime.now(),
        status="pending"
    )
    
    payloads_db.append(payload)
    
    # Start execution in background
    background_tasks.add_task(
        execute_payload_async,
        payload_id,
        request.agent_id,
        request.command,
        request.description
    )
    
    return {"payload_id": payload_id, "status": "pending"}


@app.get("/api/payloads/{payload_id}")
async def get_payload(payload_id: str):
    """Get details of a specific payload."""
    for payload in payloads_db:
        if payload.id == payload_id:
            return payload
    
    raise HTTPException(status_code=404, detail="Payload not found")


@app.get("/api/payloads/{payload_id}/export")
async def export_payload(payload_id: str):
    """Export payload data as JSON file."""
    for payload in payloads_db:
        if payload.id == payload_id:
            # Convert to JSON-serializable format
            payload_dict = payload.model_dump()
            payload_dict['timestamp'] = payload.timestamp.isoformat()
            
            return JSONResponse(
                content=payload_dict,
                headers={
                    "Content-Disposition": f"attachment; filename=payload_{payload_id}.json"
                }
            )
    
    raise HTTPException(status_code=404, detail="Payload not found")


# Mount static files for the dashboard
app.mount("/dashboard/static", StaticFiles(directory="web_dashboard"), name="static")


@app.get("/dashboard/")
async def dashboard_index():
    """Serve the dashboard main page."""
    return FileResponse("web_dashboard/index.html")


@app.get("/")
async def root():
    """Root endpoint redirecting to dashboard."""
    return {"message": "Security Monitoring Dashboard API", "dashboard_url": "/dashboard/"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)