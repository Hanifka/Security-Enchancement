/**
 * Security Monitoring Dashboard JavaScript
 * Handles API interactions, UI updates, and user interactions
 */

class DashboardApp {
    constructor() {
        this.agents = [];
        this.payloads = [];
        this.currentPayload = null;
        this.apiBase = '';
        
        this.initializeEventListeners();
        this.loadInitialData();
        this.setupPeriodicUpdates();
    }

    /**
     * Initialize event listeners
     */
    initializeEventListeners() {
        // Form submission
        document.getElementById('payload-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.executePayload();
        });

        // Next payload button
        document.getElementById('next-btn').addEventListener('click', () => {
            this.resetForm();
        });

        // Export button
        document.getElementById('export-btn').addEventListener('click', () => {
            this.exportCurrentPayload();
        });
    }

    /**
     * Load initial data from API
     */
    async loadInitialData() {
        try {
            await Promise.all([
                this.loadAgents(),
                this.loadPayloads()
            ]);
            this.updateConnectionStatus(true);
        } catch (error) {
            console.error('Failed to load initial data:', error);
            this.updateConnectionStatus(false);
            this.showError('Failed to connect to the server. Please refresh the page.');
        }
    }

    /**
     * Load agents from API
     */
    async loadAgents() {
        try {
            const response = await this.fetchWithTimeout('/api/agents');
            const data = await response.json();
            this.agents = data.agents;
            this.populateAgentSelector();
        } catch (error) {
            console.error('Failed to load agents:', error);
            throw error;
        }
    }

    /**
     * Load payloads from API
     */
    async loadPayloads() {
        try {
            const response = await this.fetchWithTimeout('/api/payloads');
            const data = await response.json();
            this.payloads = data.payloads;
            this.updatePayloadHistory();
        } catch (error) {
            console.error('Failed to load payloads:', error);
            throw error;
        }
    }

    /**
     * Populate agent selector dropdown
     */
    populateAgentSelector() {
        const selector = document.getElementById('agent-select');
        selector.innerHTML = '';

        if (this.agents.length === 0) {
            selector.innerHTML = '<option value="">No agents available</option>';
            return;
        }

        // Add online agents first
        const onlineAgents = this.agents.filter(agent => agent.status === 'online');
        const offlineAgents = this.agents.filter(agent => agent.status !== 'online');

        if (onlineAgents.length > 0) {
            const onlineGroup = document.createElement('optgroup');
            onlineGroup.label = 'Online Agents';
            onlineAgents.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.textContent = `${agent.name} (${agent.id})`;
                onlineGroup.appendChild(option);
            });
            selector.appendChild(onlineGroup);
        }

        if (offlineAgents.length > 0) {
            const offlineGroup = document.createElement('optgroup');
            offlineGroup.label = 'Offline Agents';
            offlineAgents.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.textContent = `${agent.name} (${agent.id})`;
                option.disabled = true;
                offlineGroup.appendChild(option);
            });
            selector.appendChild(offlineGroup);
        }
    }

    /**
     * Execute a new payload
     */
    async executePayload() {
        const agentId = document.getElementById('agent-select').value;
        const command = document.getElementById('command-input').value.trim();
        const description = document.getElementById('description-input').value.trim();

        if (!agentId || !command) {
            this.showError('Please select an agent and enter a command');
            return;
        }

        // Show loading state
        this.showExecutionLoading(true);
        this.hideResults();

        try {
            const response = await this.fetchWithTimeout('/api/payloads', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    agent_id: agentId,
                    command: command,
                    description: description || null
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            
            // Start polling for results
            this.pollPayloadResults(result.payload_id);

        } catch (error) {
            console.error('Failed to execute payload:', error);
            this.showError('Failed to execute payload: ' + error.message);
            this.showExecutionLoading(false);
        }
    }

    /**
     * Poll for payload execution results
     */
    async pollPayloadResults(payloadId) {
        const maxAttempts = 60; // 60 seconds max
        let attempts = 0;

        const poll = async () => {
            try {
                const response = await this.fetchWithTimeout(`/api/payloads/${payloadId}`);
                const payload = await response.json();

                if (payload.status === 'completed' || payload.status === 'failed') {
                    this.showExecutionLoading(false);
                    this.currentPayload = payload;
                    this.displayResults(payload);
                    await this.loadPayloads(); // Refresh payload history
                } else if (attempts < maxAttempts) {
                    attempts++;
                    setTimeout(poll, 1000); // Poll every second
                } else {
                    this.showExecutionLoading(false);
                    this.showError('Payload execution timed out');
                }
            } catch (error) {
                console.error('Failed to poll payload results:', error);
                this.showExecutionLoading(false);
                this.showError('Failed to get payload results');
            }
        };

        poll();
    }

    /**
     * Display payload execution results
     */
    displayResults(payload) {
        // Hide empty state, show results
        document.getElementById('empty-state').style.display = 'none';
        document.getElementById('results-section').style.display = 'block';

        // Update metadata
        document.getElementById('metadata-timestamp').textContent = new Date(payload.timestamp).toLocaleString();
        document.getElementById('metadata-duration').textContent = payload.duration_ms ? `${payload.duration_ms}ms` : 'N/A';
        document.getElementById('metadata-agent').textContent = payload.agent_id;
        document.getElementById('metadata-status').innerHTML = this.getStatusBadge(payload.status);

        // Update stdout/stderr
        document.getElementById('stdout-content').textContent = payload.stdout || 'No output';
        document.getElementById('stderr-content').textContent = payload.stderr || 'No errors';

        // Update log summary
        this.updateLogSummary(payload.log_results || {});

        // Update log entries accordion
        this.updateLogAccordion(payload.log_results || {});

        // Scroll to results
        document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });
    }

    /**
     * Update log summary cards
     */
    updateLogSummary(logResults) {
        const summaryContainer = document.getElementById('log-summary');
        summaryContainer.innerHTML = '';

        if (Object.keys(logResults).length === 0) {
            summaryContainer.innerHTML = '<div class="col-12"><p class="text-muted">No log data available</p></div>';
            return;
        }

        Object.entries(logResults).forEach(([logType, data]) => {
            const card = document.createElement('div');
            card.className = `col-md-6 col-lg-4 mb-3`;
            
            const logTypeClass = logType.toLowerCase();
            const statusClass = data.count > 0 ? 'success' : 'secondary';
            
            card.innerHTML = `
                <div class="card log-summary-card ${logTypeClass}">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6 class="card-title mb-0">${logType}</h6>
                            <span class="badge bg-${statusClass}">${data.count}</span>
                        </div>
                        <small class="text-muted">${data.path || 'Unknown path'}</small>
                    </div>
                </div>
            `;
            
            summaryContainer.appendChild(card);
        });
    }

    /**
     * Update log entries accordion
     */
    updateLogAccordion(logResults) {
        const accordionContainer = document.getElementById('log-accordion');
        accordionContainer.innerHTML = '';

        if (Object.keys(logResults).length === 0) {
            accordionContainer.innerHTML = '<p class="text-muted">No log entries to display</p>';
            return;
        }

        Object.entries(logResults).forEach(([logType, data], index) => {
            if (data.count === 0) return;

            const accordionItem = document.createElement('div');
            accordionItem.className = 'accordion-item';
            
            const accordionId = `log-${logType.toLowerCase()}`;
            const isExpanded = index === 0; // Expand first item by default
            
            accordionItem.innerHTML = `
                <h2 class="accordion-header" id="heading-${accordionId}">
                    <button class="accordion-button ${isExpanded ? '' : 'collapsed'}" 
                            type="button" 
                            data-bs-toggle="collapse" 
                            data-bs-target="#collapse-${accordionId}">
                        ${logType} Logs (${data.count})
                    </button>
                </h2>
                <div id="collapse-${accordionId}" 
                     class="accordion-collapse collapse ${isExpanded ? 'show' : ''}" 
                     data-bs-parent="#log-accordion">
                    <div class="accordion-body">
                        ${this.formatLogEntries(data.entries)}
                    </div>
                </div>
            `;
            
            accordionContainer.appendChild(accordionItem);
        });
    }

    /**
     * Format log entries for display
     */
    formatLogEntries(entries) {
        if (!entries || entries.length === 0) {
            return '<p class="text-muted">No entries</p>';
        }

        return entries.slice(0, 50).map(entry => `
            <div class="log-entry">
                <div class="d-flex justify-content-between align-items-start mb-1">
                    <span class="timestamp">${new Date(entry.timestamp).toLocaleString()}</span>
                    <span class="process-name">${entry.process || 'N/A'}${entry.pid ? `[${entry.pid}]` : ''}</span>
                </div>
                <div class="message-preview">${this.escapeHtml(entry.message)}</div>
                ${entry.host ? `<small class="text-muted">Host: ${entry.host}</small>` : ''}
            </div>
        `).join('');
    }

    /**
     * Update payload history sidebar
     */
    updatePayloadHistory() {
        const historyContainer = document.getElementById('payload-history');
        const emptyState = document.getElementById('history-empty');

        if (this.payloads.length === 0) {
            historyContainer.innerHTML = '';
            emptyState.style.display = 'block';
            return;
        }

        emptyState.style.display = 'none';
        historyContainer.innerHTML = '';

        // Sort by timestamp (newest first)
        const sortedPayloads = [...this.payloads].sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );

        sortedPayloads.forEach(payload => {
            const item = document.createElement('div');
            item.className = `list-group-item payload-history-item ${payload.status}`;
            
            const agent = this.agents.find(a => a.id === payload.agent_id);
            const agentName = agent ? agent.name : payload.agent_id;
            
            item.innerHTML = `
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <h6 class="mb-1">${this.truncateText(payload.command, 50)}</h6>
                        <small class="text-muted">${agentName}</small>
                    </div>
                    <div class="text-end">
                        ${this.getStatusBadge(payload.status)}
                        <div><small class="text-muted">${new Date(payload.timestamp).toLocaleTimeString()}</small></div>
                    </div>
                </div>
                ${payload.description ? `<small class="text-muted d-block mt-1">${payload.description}</small>` : ''}
            `;

            item.addEventListener('click', () => {
                this.loadPayloadDetails(payload.id);
            });

            historyContainer.appendChild(item);
        });
    }

    /**
     * Load and display payload details
     */
    async loadPayloadDetails(payloadId) {
        try {
            const response = await this.fetchWithTimeout(`/api/payloads/${payloadId}`);
            const payload = await response.json();
            
            this.currentPayload = payload;
            this.displayResults(payload);
            
            // Update active state in history
            document.querySelectorAll('.payload-history-item').forEach(item => {
                item.classList.remove('active');
            });
            event.currentTarget.classList.add('active');
            
        } catch (error) {
            console.error('Failed to load payload details:', error);
            this.showError('Failed to load payload details');
        }
    }

    /**
     * Export current payload as JSON
     */
    async exportCurrentPayload() {
        if (!this.currentPayload) {
            this.showError('No payload to export');
            return;
        }

        try {
            const response = await this.fetchWithTimeout(`/api/payloads/${this.currentPayload.id}/export`);
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `payload_${this.currentPayload.id}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
        } catch (error) {
            console.error('Failed to export payload:', error);
            this.showError('Failed to export payload');
        }
    }

    /**
     * Reset the payload form
     */
    resetForm() {
        document.getElementById('payload-form').reset();
        this.hideResults();
        document.getElementById('empty-state').style.display = 'block';
    }

    /**
     * Show/hide execution loading state
     */
    showExecutionLoading(show) {
        const loadingElement = document.getElementById('execution-loading');
        const formElement = document.getElementById('payload-form');
        
        if (show) {
            loadingElement.style.display = 'block';
            formElement.style.display = 'none';
        } else {
            loadingElement.style.display = 'none';
            formElement.style.display = 'block';
        }
    }

    /**
     * Hide results section
     */
    hideResults() {
        document.getElementById('results-section').style.display = 'none';
        document.getElementById('empty-state').style.display = 'block';
    }

    /**
     * Update connection status indicator
     */
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connection-status');
        
        if (connected) {
            statusElement.className = 'badge bg-success';
            statusElement.innerHTML = '<i class="bi bi-wifi"></i> Connected';
        } else {
            statusElement.className = 'badge bg-danger';
            statusElement.innerHTML = '<i class="bi bi-wifi-off"></i> Disconnected';
        }
    }

    /**
     * Show error message in modal
     */
    showError(message) {
        document.getElementById('error-message').textContent = message;
        const errorModal = new bootstrap.Modal(document.getElementById('error-modal'));
        errorModal.show();
    }

    /**
     * Get status badge HTML
     */
    getStatusBadge(status) {
        const badges = {
            'completed': '<span class="badge bg-success">Completed</span>',
            'failed': '<span class="badge bg-danger">Failed</span>',
            'running': '<span class="badge bg-warning">Running</span>',
            'pending': '<span class="badge bg-info">Pending</span>'
        };
        return badges[status] || '<span class="badge bg-secondary">Unknown</span>';
    }

    /**
     * Utility function to truncate text
     */
    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - 3) + '...';
    }

    /**
     * Utility function to escape HTML
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Fetch with timeout
     */
    async fetchWithTimeout(url, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    /**
     * Setup periodic updates
     */
    setupPeriodicUpdates() {
        // Update payload history every 30 seconds
        setInterval(() => {
            this.loadPayloads().catch(error => {
                console.error('Failed to update payload history:', error);
            });
        }, 30000);

        // Check connection status every 10 seconds
        setInterval(() => {
            this.fetchWithTimeout('/api/agents')
                .then(() => this.updateConnectionStatus(true))
                .catch(() => this.updateConnectionStatus(false));
        }, 10000);
    }
}

// Initialize the dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboardApp = new DashboardApp();
});