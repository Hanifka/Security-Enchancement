#!/bin/bash
# Startup script for the Security Monitoring Dashboard

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the project directory
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
if [ ! -f "venv/pyvenv.cfg" ] || [ requirements.txt -nt venv/pyvenv.cfg ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Set PYTHONPATH to include the project directory
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# Start the FastAPI server
echo "Starting Security Monitoring Dashboard..."
echo "Dashboard will be available at: http://localhost:8000/dashboard/"
echo "API documentation available at: http://localhost:8000/docs"
echo "Press Ctrl+C to stop the server"
echo ""

python3 main.py