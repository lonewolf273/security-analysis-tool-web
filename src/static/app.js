// Global variables
let scanResults = [];

// DOM elements
const logContent = document.getElementById('log-content');
const logFile = document.getElementById('log-file');
const scanTarget = document.getElementById('scan-target');
const analyzeLogsBtn = document.getElementById('analyze-logs-btn');
const automatedScanBtn = document.getElementById('automated-scan-btn');
const clearResultsBtn = document.getElementById('clear-results-btn');
const scanResultsDiv = document.getElementById('scan-results');
const loadingScan = document.getElementById('loading-scan');
const loadingViz = document.getElementById('loading-viz');
const loadingReport = document.getElementById('loading-report');
const portChartBtn = document.getElementById('port-chart-btn');
const abuseChartBtn = document.getElementById('abuse-chart-btn');
const dashboardBtn = document.getElementById('dashboard-btn');
const generateReportBtn = document.getElementById('generate-report-btn');
const visualizationDisplay = document.getElementById('visualization-display');
const statusMessage = document.getElementById('status-message');
const statusIcon = document.getElementById('status-icon');
const statusText = document.getElementById('status-text');

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    analyzeLogsBtn.addEventListener('click', analyzeLogFile);
    automatedScanBtn.addEventListener('click', performAutomatedScan);
    clearResultsBtn.addEventListener('click', clearResults);
    portChartBtn.addEventListener('click', () => generateVisualization('port-distribution'));
    abuseChartBtn.addEventListener('click', () => generateVisualization('abuse-confidence'));
    dashboardBtn.addEventListener('click', () => generateVisualization('summary-dashboard'));
    generateReportBtn.addEventListener('click', generatePDFReport);
    logFile.addEventListener('change', handleFileUpload);
});

// Tab functionality
function showTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => content.classList.remove('active'));
    
    // Remove active class from all tab buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => button.classList.remove('active'));
    
    // Show selected tab content
    document.getElementById(tabName + '-tab').classList.add('active');
    
    // Add active class to clicked button
    event.target.classList.add('active');
}

// File upload handler
function handleFileUpload(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            logContent.value = e.target.result;
        };
        reader.readAsText(file);
    }
}

// Analyze log file
async function analyzeLogFile() {
    const content = logContent.value.trim();
    if (!content) {
        showStatus('error', 'Please provide log content to analyze.');
        return;
    }

    setLoading('scan', true);
    
    try {
        const response = await fetch('/api/security/scan/log', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ log_content: content })
        });

        const data = await response.json();
        
        if (data.success) {
            scanResults = data.results;
            displayScanResults(scanResults);
            enableVisualizationButtons();
            showStatus('success', 'Log analysis completed successfully.');
        } else {
            showStatus('error', data.error || 'Failed to analyze log file.');
        }
    } catch (error) {
        showStatus('error', 'Error connecting to server: ' + error.message);
    } finally {
        setLoading('scan', false);
    }
}

// Perform automated scan
async function performAutomatedScan() {
    const target = scanTarget.value.trim();
    if (!target) {
        showStatus('error', 'Please provide a target IP or range to scan.');
        return;
    }

    setLoading('scan', true);
    
    try {
        const response = await fetch('/api/security/scan/automated', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target: target })
        });

        const data = await response.json();
        
        if (data.success) {
            scanResults = data.results;
            displayScanResults(scanResults);
            enableVisualizationButtons();
            showStatus('success', 'Automated scan completed successfully.');
        } else {
            showStatus('error', data.error || 'Failed to perform automated scan.');
        }
    } catch (error) {
        showStatus('error', 'Error connecting to server: ' + error.message);
    } finally {
        setLoading('scan', false);
    }
}

// Display scan results
function displayScanResults(results) {
    let html = '<div class="space-y-4">';
    
    results.forEach((result, index) => {
        const ip = result.ip || 'Unknown';
        html += `
            <div class="bg-white border border-gray-200 rounded-lg p-4">
                <h4 class="font-semibold text-lg text-gray-800 mb-3">
                    <i class="fas fa-server mr-2 text-blue-600"></i>
                    Result ${index + 1}: ${ip}
                </h4>
                
                <!-- Nmap Results -->
                <div class="mb-4">
                    <h5 class="font-medium text-gray-700 mb-2">
                        <i class="fas fa-network-wired mr-2"></i>Network Scan Results
                    </h5>
        `;
        
        const nmapResults = result.nmap_results || {};
        if (nmapResults.error) {
            html += `<p class="text-red-600 text-sm">Error: ${nmapResults.error}</p>`;
        } else {
            html += `<p class="text-sm text-gray-600 mb-2">Host Status: <span class="font-medium">${nmapResults.status || 'Unknown'}</span></p>`;
            
            const ports = nmapResults.ports || [];
            if (ports.length > 0) {
                html += '<div class="bg-gray-50 p-3 rounded"><h6 class="font-medium text-sm text-gray-700 mb-2">Open Ports:</h6>';
                ports.forEach(port => {
                    html += `
                        <div class="text-sm text-gray-600 mb-1">
                            Port ${port.port}/${port.protocol}: ${port.state} - ${port.name}
                            ${port.product ? `(${port.product} ${port.version || ''})` : ''}
                        </div>
                    `;
                });
                html += '</div>';
            } else {
                html += '<p class="text-sm text-gray-600">No open ports found.</p>';
            }
        }
        
        html += '</div>';
        
        // AbuseIPDB Results
        html += `
            <div>
                <h5 class="font-medium text-gray-700 mb-2">
                    <i class="fas fa-shield-alt mr-2"></i>Threat Intelligence Results
                </h5>
        `;
        
        const abuseResults = result.abuseipdb_results || {};
        if (abuseResults.error) {
            html += `<p class="text-red-600 text-sm">Error: ${abuseResults.error}</p>`;
        } else {
            const confidence = abuseResults.abuseConfidencePercentage || 0;
            let riskClass = 'text-green-600';
            let riskLevel = 'CLEAN';
            
            if (confidence > 75) {
                riskClass = 'text-red-600';
                riskLevel = 'CRITICAL';
            } else if (confidence > 50) {
                riskClass = 'text-red-500';
                riskLevel = 'HIGH';
            } else if (confidence > 25) {
                riskClass = 'text-yellow-600';
                riskLevel = 'MEDIUM';
            } else if (confidence > 0) {
                riskClass = 'text-yellow-500';
                riskLevel = 'LOW';
            }
            
            html += `
                <div class="bg-gray-50 p-3 rounded space-y-1">
                    <div class="text-sm text-gray-600">Abuse Confidence: <span class="font-medium">${confidence}%</span></div>
                    <div class="text-sm text-gray-600">Country: <span class="font-medium">${abuseResults.countryCode || 'N/A'}</span></div>
                    <div class="text-sm text-gray-600">ISP: <span class="font-medium">${abuseResults.isp || 'N/A'}</span></div>
                    <div class="text-sm text-gray-600">Total Reports: <span class="font-medium">${abuseResults.totalReports || 'N/A'}</span></div>
                    <div class="text-sm">Risk Level: <span class="font-bold ${riskClass}">${riskLevel}</span></div>
                </div>
            `;
        }
        
        html += '</div></div>';
    });
    
    html += '</div>';
    scanResultsDiv.innerHTML = html;
}

// Enable visualization buttons
function enableVisualizationButtons() {
    portChartBtn.disabled = false;
    abuseChartBtn.disabled = false;
    dashboardBtn.disabled = false;
    generateReportBtn.disabled = false;
}

// Generate visualization
async function generateVisualization(type) {
    if (scanResults.length === 0) {
        showStatus('error', 'No scan results available for visualization.');
        return;
    }

    setLoading('viz', true);
    
    try {
        const response = await fetch(`/api/security/visualizations/${type}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ scan_results: scanResults })
        });

        const data = await response.json();
        
        if (data.success && data.chart_data) {
            visualizationDisplay.innerHTML = `
                <img src="${data.chart_data}" alt="${type} chart" class="w-full h-auto rounded-lg shadow-md">
            `;
            showStatus('success', 'Visualization generated successfully.');
        } else {
            visualizationDisplay.innerHTML = `
                <p class="text-gray-500 text-center py-8">${data.message || 'No data available for visualization.'}</p>
            `;
            showStatus('warning', data.message || 'No data available for visualization.');
        }
    } catch (error) {
        showStatus('error', 'Error generating visualization: ' + error.message);
    } finally {
        setLoading('viz', false);
    }
}

// Generate PDF report
async function generatePDFReport() {
    if (scanResults.length === 0) {
        showStatus('error', 'No scan results available to generate report.');
        return;
    }

    setLoading('report', true);
    
    try {
        const response = await fetch('/api/security/report/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ scan_results: scanResults })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'security_report.pdf';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            showStatus('success', 'PDF report generated and downloaded successfully.');
        } else {
            const data = await response.json();
            showStatus('error', data.error || 'Failed to generate PDF report.');
        }
    } catch (error) {
        showStatus('error', 'Error generating report: ' + error.message);
    } finally {
        setLoading('report', false);
    }
}

// Clear results
function clearResults() {
    scanResults = [];
    scanResultsDiv.innerHTML = '<p class="text-gray-500 text-center py-8">No scan results yet. Start a scan to see results here.</p>';
    visualizationDisplay.innerHTML = '<p class="text-gray-500 text-center py-8">No visualization to display. Please run a scan first.</p>';
    logContent.value = '';
    scanTarget.value = '';
    
    // Disable buttons
    portChartBtn.disabled = true;
    abuseChartBtn.disabled = true;
    dashboardBtn.disabled = true;
    generateReportBtn.disabled = true;
    
    showStatus('info', 'Results cleared successfully.');
}

// Set loading state
function setLoading(type, isLoading) {
    const loadingElement = document.getElementById(`loading-${type}`);
    if (isLoading) {
        loadingElement.classList.add('active');
    } else {
        loadingElement.classList.remove('active');
    }
}

// Show status message
function showStatus(type, message) {
    const iconMap = {
        success: '<i class="fas fa-check-circle text-green-500"></i>',
        error: '<i class="fas fa-exclamation-circle text-red-500"></i>',
        warning: '<i class="fas fa-exclamation-triangle text-yellow-500"></i>',
        info: '<i class="fas fa-info-circle text-blue-500"></i>'
    };
    
    statusIcon.innerHTML = iconMap[type] || iconMap.info;
    statusText.textContent = message;
    statusMessage.classList.remove('hidden');
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        statusMessage.classList.add('hidden');
    }, 5000);
}

