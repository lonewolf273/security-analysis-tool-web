# Security Analysis Tool - Web Service

A comprehensive web-based security analysis tool that integrates network scanning, threat intelligence, data visualization, and automated report generation. This tool provides a modern web interface for conducting security assessments and generating professional reports.

## Features

- **Web-Based Interface**: Modern, responsive web interface accessible via any browser
- **Network Scanning**: Automated Nmap port scanning and service enumeration
- **Log Analysis**: Parse log files to extract IP addresses for security analysis
- **Threat Intelligence**: Integration with AbuseIPDB API for IP reputation checking
- **Data Visualization**: Interactive charts and graphs using Matplotlib
- **PDF Reports**: Comprehensive security reports with findings and recommendations
- **RESTful API**: Complete API for programmatic access to all functionality

## Architecture

The application follows a modern web architecture with:

- **Backend**: Flask-based REST API with CORS support
- **Frontend**: HTML/CSS/JavaScript with Tailwind CSS styling
- **Database**: SQLite for session management (optional)
- **Security**: Input validation, error handling, and secure API design

## Requirements

### System Requirements
- Python 3.11 or higher
- Nmap installed on the system
- Internet connection for AbuseIPDB API access
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Python Dependencies
```
Flask==3.1.1
flask-cors==6.0.0
Flask-SQLAlchemy==3.1.1
python-nmap==0.7.1
matplotlib==3.10.3
fpdf2==2.8.3
requests==2.32.4
numpy==2.3.1
pillow==11.3.0
```

## Installation

### 1. Install System Dependencies

**Install Nmap** (if not already installed):
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap

# Windows
# Download installer from https://nmap.org/download.html
```

### 2. Set Up the Application

**Clone or extract the project files:**
```bash
# Extract the project to your desired directory
cd /path/to/your/project
```

**Install Python dependencies:**
```bash
# Navigate to the project directory
cd security_tool_web

# Activate virtual environment (if using one)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

**Configure AbuseIPDB API Key:**
1. Register for a free account at [AbuseIPDB](https://www.abuseipdb.com/)
2. Obtain your API key from the dashboard
3. Update the API key in `src/security_analyzer.py`:
   ```python
   self.abuseipdb_api_key = "YOUR_API_KEY_HERE"
   ```

## Usage

### Starting the Web Service

```bash
# Navigate to the project directory
cd security_tool_web

# Activate virtual environment (if using one)
source venv/bin/activate

# Start the Flask development server
python src/main.py
```

The web service will be available at:
- Local access: http://localhost:5000
- Network access: http://[your-ip]:5000

### Web Interface

#### 1. Scan & Analysis Tab
- **Log File Analysis**: Upload log files or paste log content for IP extraction and analysis
- **Automated Scan**: Enter target IP addresses or ranges for network scanning
- **Real-time Results**: View scan results and threat intelligence data

#### 2. Visualizations Tab
- **Port Distribution**: Bar chart showing open ports across scanned hosts
- **Abuse Confidence**: Pie chart displaying threat intelligence risk levels
- **Summary Dashboard**: Comprehensive overview with multiple charts

#### 3. Reports Tab
- **PDF Generation**: Create comprehensive security reports
- **Download Reports**: Automatically download generated PDF reports

### API Endpoints

The web service provides a RESTful API for programmatic access:

#### Security Analysis Endpoints

**POST /api/security/scan/automated**
- Perform automated network scan
- Request body: `{"target": "192.168.1.1"}`
- Response: Scan results with Nmap and AbuseIPDB data

**POST /api/security/scan/log**
- Analyze log file content
- Request body: `{"log_content": "log file content here"}`
- Response: Analysis results for extracted IP addresses

#### Visualization Endpoints

**POST /api/security/visualizations/port-distribution**
- Generate port distribution chart
- Request body: `{"scan_results": [...]}`
- Response: Base64-encoded PNG image

**POST /api/security/visualizations/abuse-confidence**
- Generate abuse confidence chart
- Request body: `{"scan_results": [...]}`
- Response: Base64-encoded PNG image

**POST /api/security/visualizations/summary-dashboard**
- Generate summary dashboard
- Request body: `{"scan_results": [...]}`
- Response: Base64-encoded PNG image

#### Report Generation Endpoint

**POST /api/security/report/generate**
- Generate PDF security report
- Request body: `{"scan_results": [...]}`
- Response: PDF file download

#### Health Check Endpoint

**GET /api/security/health**
- Check service health status
- Response: `{"status": "healthy", "service": "Security Analysis Tool"}`

### Example API Usage

```bash
# Perform automated scan
curl -X POST http://localhost:5000/api/security/scan/automated \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'

# Generate visualization
curl -X POST http://localhost:5000/api/security/visualizations/summary-dashboard \
  -H "Content-Type: application/json" \
  -d '{"scan_results": [...]}'

# Generate PDF report
curl -X POST http://localhost:5000/api/security/report/generate \
  -H "Content-Type: application/json" \
  -d '{"scan_results": [...]}' \
  --output security_report.pdf
```

## File Structure

```
security_tool_web/
├── src/
│   ├── main.py                 # Flask application entry point
│   ├── security_analyzer.py    # Core security analysis logic
│   ├── pdf_generator.py        # PDF report generation
│   ├── routes/
│   │   ├── security.py         # Security API endpoints
│   │   └── user.py            # User management endpoints
│   ├── models/
│   │   └── user.py            # Database models
│   ├── static/
│   │   ├── index.html         # Main web interface
│   │   └── app.js             # Frontend JavaScript
│   └── database/
│       └── app.db             # SQLite database
├── venv/                      # Virtual environment
├── requirements.txt           # Python dependencies
└── README.md                 # This documentation
```

## Security Considerations

### Ethical Use
- Only scan networks and systems you own or have explicit permission to test
- Respect rate limits and terms of service for external APIs
- Use responsibly and in compliance with local laws and regulations

### Data Privacy
- AbuseIPDB API calls may log IP addresses being queried
- Generated reports may contain sensitive network information
- Store and share reports securely
- Consider implementing authentication for production deployments

### Network Impact
- Nmap scans may be detected by intrusion detection systems
- Consider scan timing and intensity for production networks
- Test in isolated environments when possible

### Production Deployment
- Use a production WSGI server (e.g., Gunicorn, uWSGI) instead of Flask's development server
- Implement proper authentication and authorization
- Use HTTPS for secure communication
- Configure proper firewall rules and access controls

## Troubleshooting

### Common Issues

#### Service Won't Start
```
Error: Address already in use
```
**Solution**: Another service is using port 5000. Either stop the other service or change the port in `src/main.py`

#### Nmap Not Found
```
Error: Nmap not found in system PATH
```
**Solution**: Install Nmap and ensure it's in your system PATH

#### AbuseIPDB API Errors
```
AbuseIPDB API Error: 401 Unauthorized
```
**Solution**: Verify your API key is correct and active

#### Permission Denied
```
Permission denied when scanning
```
**Solution**: Run with appropriate privileges or scan only permitted targets

#### CORS Errors
```
Access to fetch blocked by CORS policy
```
**Solution**: Ensure Flask-CORS is properly configured (already included in the application)

### Performance Optimization

- **Large Networks**: Use smaller IP ranges or implement batch processing
- **Memory Usage**: Clear results between scans for large datasets
- **API Limits**: AbuseIPDB free tier allows 1000 queries per day
- **Concurrent Requests**: Consider implementing request queuing for high-traffic scenarios

## Development

### Code Structure
- **MVC Pattern**: Separation of API routes, business logic, and data models
- **RESTful Design**: Clean API endpoints following REST principles
- **Error Handling**: Comprehensive error handling and user feedback
- **Modular Design**: Independent modules for easy maintenance and testing

### Extending the Tool
- **Additional APIs**: Add more threat intelligence sources
- **New Visualizations**: Implement custom chart types
- **Export Formats**: Support additional report formats (CSV, JSON, XML)
- **Scanning Options**: Add more Nmap scan types and options
- **Authentication**: Implement user authentication and session management

### Testing
```bash
# Run basic functionality tests
python -c "
from src.security_analyzer import SecurityAnalyzer
analyzer = SecurityAnalyzer()
result = analyzer.perform_nmap_scan('127.0.0.1')
print('Test passed' if 'host' in result else 'Test failed')
"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support

For issues, questions, or contributions:
- Review the troubleshooting section
- Check system requirements and dependencies
- Ensure proper configuration of API keys
- Test with simple scenarios first
- Verify network connectivity and permissions

## Changelog

### Version 2.0.0 (Web Service)
- Complete re-architecture as a web service
- Flask-based REST API backend
- Modern web interface with responsive design
- Real-time scan results and visualizations
- Improved error handling and user feedback
- CORS support for cross-origin requests
- Comprehensive API documentation

### Version 1.0.0 (Desktop Application)
- Initial release with PyQt6 GUI
- Core Nmap and AbuseIPDB integration
- Basic visualization and PDF generation
- Desktop-only functionality

