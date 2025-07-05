from fpdf import FPDF
from datetime import datetime
import os
import tempfile
import base64
import io

class SecurityReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
    def generate_report(self, scan_results, visualizations=None, output_path="security_report.pdf"):
        """Generate a comprehensive PDF report from scan results"""
        
        # Reset PDF for new report
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
        # Add title page
        self._add_title_page()
        
        # Add executive summary
        self._add_executive_summary(scan_results)
        
        # Add detailed findings
        self._add_detailed_findings(scan_results)
        
        # Add visualizations if provided
        if visualizations:
            self._add_visualizations(visualizations)
        
        # Add recommendations
        self._add_recommendations(scan_results)
        
        # Save the PDF
        self.pdf.output(output_path)
        return output_path
    
    def _add_title_page(self):
        """Add title page to the report"""
        self.pdf.add_page()
        
        # Title
        self.pdf.set_font('Arial', 'B', 24)
        self.pdf.cell(0, 20, 'Security Analysis Report', 0, 1, 'C')
        
        # Subtitle
        self.pdf.set_font('Arial', '', 16)
        self.pdf.cell(0, 10, 'Log Management and Network Security Assessment', 0, 1, 'C')
        
        # Date
        self.pdf.ln(20)
        self.pdf.set_font('Arial', '', 12)
        current_date = datetime.now().strftime("%B %d, %Y")
        self.pdf.cell(0, 10, f'Report Generated: {current_date}', 0, 1, 'C')
        
        # Add some spacing
        self.pdf.ln(30)
        
        # Report description
        self.pdf.set_font('Arial', '', 11)
        description = """This report contains the results of a comprehensive security analysis including:
        
- Network port scanning and service enumeration
- IP reputation analysis using AbuseIPDB
- Vulnerability assessment findings
- Security recommendations and remediation steps

This assessment was conducted using automated tools and should be reviewed by qualified security personnel."""
        
        self.pdf.multi_cell(0, 8, description)
    
    def _add_executive_summary(self, scan_results):
        """Add executive summary section"""
        self.pdf.add_page()
        
        # Section header
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'Executive Summary', 0, 1, 'L')
        self.pdf.ln(5)
        
        # Calculate summary statistics
        total_ips = len(scan_results)
        total_open_ports = 0
        high_risk_ips = 0
        unique_services = set()
        
        for result in scan_results:
            nmap_results = result.get('nmap_results', {})
            ports = nmap_results.get('ports', [])
            for port in ports:
                if port['state'] == 'open':
                    total_open_ports += 1
                    if port['name']:
                        unique_services.add(port['name'])
            
            abuse_results = result.get('abuseipdb_results', {})
            if abuse_results.get('abuseConfidencePercentage', 0) > 50:
                high_risk_ips += 1
        
        # Summary content
        self.pdf.set_font('Arial', '', 11)
        summary_text = f"""Assessment Overview:

- Total IP addresses analyzed: {total_ips}
- Total open ports discovered: {total_open_ports}
- Unique services identified: {len(unique_services)}
- High-risk IP addresses: {high_risk_ips}

Risk Assessment:
"""
        
        if high_risk_ips > 0:
            summary_text += f"WARNING: {high_risk_ips} IP address(es) flagged as high-risk by threat intelligence sources.\n"
        else:
            summary_text += "GOOD: No high-risk IP addresses identified in threat intelligence databases.\n"
        
        if total_open_ports > 0:
            summary_text += f"INFO: {total_open_ports} open port(s) discovered across all scanned hosts.\n"
        else:
            summary_text += "SECURE: No open ports discovered on scanned hosts.\n"
        
        summary_text += f"\nThis report provides detailed findings and recommendations for each discovered service and potential security concern."
        
        self.pdf.multi_cell(0, 6, summary_text)
    
    def _add_detailed_findings(self, scan_results):
        """Add detailed findings for each IP address"""
        self.pdf.add_page()
        
        # Section header
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'Detailed Findings', 0, 1, 'L')
        self.pdf.ln(5)
        
        for i, result in enumerate(scan_results, 1):
            ip = result.get('ip', 'Unknown')
            
            # IP header
            self.pdf.set_font('Arial', 'B', 14)
            self.pdf.cell(0, 10, f'{i}. Analysis Results for {ip}', 0, 1, 'L')
            self.pdf.ln(3)
            
            # Nmap results
            self.pdf.set_font('Arial', 'B', 12)
            self.pdf.cell(0, 8, 'Network Scan Results:', 0, 1, 'L')
            
            nmap_results = result.get('nmap_results', {})
            self.pdf.set_font('Arial', '', 10)
            
            if 'error' in nmap_results:
                self.pdf.cell(0, 6, f'Error: {nmap_results["error"]}', 0, 1, 'L')
            else:
                host_status = nmap_results.get('status', 'Unknown')
                self.pdf.cell(0, 6, f'Host Status: {host_status}', 0, 1, 'L')
                
                ports = nmap_results.get('ports', [])
                if ports:
                    self.pdf.cell(0, 6, 'Open Ports:', 0, 1, 'L')
                    for port in ports:
                        port_info = f"  - Port {port['port']}/{port['protocol']}: {port['state']} - {port['name']}"
                        if port.get('product'):
                            port_info += f" ({port['product']} {port.get('version', '')})"
                        self.pdf.cell(0, 5, port_info, 0, 1, 'L')
                else:
                    self.pdf.cell(0, 6, 'No open ports found', 0, 1, 'L')
            
            self.pdf.ln(3)
            
            # AbuseIPDB results
            self.pdf.set_font('Arial', 'B', 12)
            self.pdf.cell(0, 8, 'Threat Intelligence Results:', 0, 1, 'L')
            
            abuse_results = result.get('abuseipdb_results', {})
            self.pdf.set_font('Arial', '', 10)
            
            if 'error' in abuse_results:
                self.pdf.cell(0, 6, f'Error: {abuse_results["error"]}', 0, 1, 'L')
            else:
                confidence = abuse_results.get('abuseConfidencePercentage', 0)
                country = abuse_results.get('countryCode', 'N/A')
                isp = abuse_results.get('isp', 'N/A')
                is_public = abuse_results.get('isPublic', 'N/A')
                total_reports = abuse_results.get('totalReports', 0)
                
                self.pdf.cell(0, 5, f'Abuse Confidence: {confidence}%', 0, 1, 'L')
                self.pdf.cell(0, 5, f'Country: {country}', 0, 1, 'L')
                self.pdf.cell(0, 5, f'ISP: {isp}', 0, 1, 'L')
                self.pdf.cell(0, 5, f'Public IP: {is_public}', 0, 1, 'L')
                self.pdf.cell(0, 5, f'Total Reports: {total_reports}', 0, 1, 'L')
                
                # Risk assessment
                if confidence > 75:
                    risk_level = "CRITICAL"
                elif confidence > 50:
                    risk_level = "HIGH"
                elif confidence > 25:
                    risk_level = "MEDIUM"
                elif confidence > 0:
                    risk_level = "LOW"
                else:
                    risk_level = "CLEAN"
                
                self.pdf.set_font('Arial', 'B', 10)
                self.pdf.cell(0, 6, f'Risk Level: {risk_level}', 0, 1, 'L')
            
            self.pdf.ln(8)
            
            # Check if we need a new page
            if self.pdf.get_y() > 250:
                self.pdf.add_page()
    
    def _add_visualizations(self, visualizations):
        """Add visualization charts to the report"""
        self.pdf.add_page()
        
        # Section header
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'Data Visualizations', 0, 1, 'L')
        self.pdf.ln(5)
        
        # Add each visualization
        for viz_name, viz_data in visualizations.items():
            if viz_data and viz_data.startswith('data:image/png;base64,'):
                # Extract base64 data
                base64_data = viz_data.split(',')[1]
                
                # Decode base64 to bytes
                image_data = base64.b64decode(base64_data)
                
                # Save to temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
                temp_file.write(image_data)
                temp_file.close()
                
                # Add chart title
                self.pdf.set_font('Arial', 'B', 12)
                chart_title = viz_name.replace('_', ' ').title()
                self.pdf.cell(0, 8, chart_title, 0, 1, 'L')
                self.pdf.ln(2)
                
                # Add image to PDF
                try:
                    # Calculate image dimensions to fit page
                    img_width = 180  # Max width
                    self.pdf.image(temp_file.name, x=15, w=img_width)
                    self.pdf.ln(10)
                except Exception as e:
                    self.pdf.set_font('Arial', '', 10)
                    self.pdf.cell(0, 6, f'Error displaying chart: {str(e)}', 0, 1, 'L')
                
                # Clean up temporary file
                try:
                    os.remove(temp_file.name)
                except:
                    pass
                
                # Check if we need a new page
                if self.pdf.get_y() > 200:
                    self.pdf.add_page()
    
    def _add_recommendations(self, scan_results):
        """Add security recommendations section"""
        self.pdf.add_page()
        
        # Section header
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'Security Recommendations', 0, 1, 'L')
        self.pdf.ln(5)
        
        # Analyze results to generate specific recommendations
        recommendations = []
        
        # Check for high-risk IPs
        high_risk_ips = []
        for result in scan_results:
            abuse_results = result.get('abuseipdb_results', {})
            if abuse_results.get('abuseConfidencePercentage', 0) > 50:
                high_risk_ips.append(result.get('ip'))
        
        if high_risk_ips:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'Block High-Risk IP Addresses',
                'description': f'The following IP addresses have been flagged as high-risk: {", ".join(high_risk_ips)}. Consider blocking these IPs at the firewall level and investigating any recent connections from these sources.'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'title': 'Implement Network Segmentation',
                'description': 'Consider implementing network segmentation to limit the blast radius of potential security incidents. Critical systems should be isolated from general user networks.'
            },
            {
                'priority': 'MEDIUM',
                'title': 'Regular Security Monitoring',
                'description': 'Implement continuous monitoring of network traffic and maintain updated threat intelligence feeds to detect emerging threats.'
            },
            {
                'priority': 'LOW',
                'title': 'Regular Security Assessments',
                'description': 'Conduct regular security assessments and penetration testing to identify new vulnerabilities and ensure security controls remain effective.'
            }
        ])
        
        # Add recommendations to PDF
        for rec in recommendations:
            self.pdf.set_font('Arial', 'B', 12)
            self.pdf.cell(0, 8, f'[{rec["priority"]}] {rec["title"]}', 0, 1, 'L')
            
            self.pdf.set_font('Arial', '', 10)
            self.pdf.multi_cell(0, 5, rec['description'])
            self.pdf.ln(3)
        
        # Add footer
        self.pdf.ln(10)
        self.pdf.set_font('Arial', 'I', 9)
        footer_text = """Note: This report is generated by automated tools and should be reviewed by qualified security personnel. 
The recommendations provided are general guidelines and should be adapted to your specific environment and security requirements."""
        self.pdf.multi_cell(0, 4, footer_text)

