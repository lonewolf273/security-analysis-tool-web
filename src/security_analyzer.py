import nmap
import re
import requests
import io
import base64
from collections import Counter
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for web service
import matplotlib.pyplot as plt
import numpy as np

class SecurityAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.abuseipdb_api_key = "c5427831055ce4f85372e54a02f53c339626d9ba7e213b935c5310ee77ea09b20fa814cc93adaaf4"

    def parse_logs_for_ips(self, log_content):
        """Extract IP addresses from log content"""
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ips = re.findall(ip_pattern, log_content)
        return list(set(ips))  # Return unique IPs

    def perform_nmap_scan(self, target_ip):
        """Perform Nmap scan on target IP"""
        scan_results = {}
        try:
            self.nm.scan(target_ip, '20-1024', arguments='-sV')
            if target_ip in self.nm.all_hosts():
                scan_results['host'] = target_ip
                scan_results['status'] = self.nm[target_ip].state()
                scan_results['ports'] = []
                for proto in self.nm[target_ip].all_protocols():
                    lport = self.nm[target_ip][proto].keys()
                    for port in lport:
                        port_info = self.nm[target_ip][proto][port]
                        scan_results['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'name': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        })
            return scan_results
        except nmap.PortScannerError as e:
            return {'error': f"Nmap Scan Error: {e}"}
        except Exception as e:
            return {'error': f"An unexpected error occurred during Nmap scan: {e}"}

    def get_abuseipdb_report(self, ip_address):
        """Get AbuseIPDB report for IP address"""
        if not self.abuseipdb_api_key or self.abuseipdb_api_key == "YOUR_ABUSEIPDB_API_KEY":
            return {"error": "AbuseIPDB API key not configured."}

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
        headers = {
            'Key': self.abuseipdb_api_key,
            'Accept': 'application/json'
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data.get('data', {})
        except requests.exceptions.RequestException as e:
            return {'error': f"AbuseIPDB API Error: {e}"}
        except Exception as e:
            return {'error': f"An unexpected error occurred during AbuseIPDB query: {e}"}

    def analyze_log_file_content(self, log_content):
        """Analyze log content and return results"""
        ips = self.parse_logs_for_ips(log_content)
        full_analysis_results = []
        for ip in ips:
            nmap_res = self.perform_nmap_scan(ip)
            abuse_res = self.get_abuseipdb_report(ip)
            full_analysis_results.append({
                'ip': ip,
                'nmap_results': nmap_res,
                'abuseipdb_results': abuse_res
            })
        return full_analysis_results

    def perform_automated_scan(self, target_ip_or_range):
        """Perform automated scan on target IP or range"""
        full_analysis_results = []
        ips_to_scan = [target_ip_or_range]  # Assuming single IP for now

        for ip in ips_to_scan:
            nmap_res = self.perform_nmap_scan(ip)
            abuse_res = self.get_abuseipdb_report(ip)
            full_analysis_results.append({
                'ip': ip,
                'nmap_results': nmap_res,
                'abuseipdb_results': abuse_res
            })
        return full_analysis_results

class SecurityDataVisualizer:
    def __init__(self):
        plt.style.use('default')
        
    def create_port_distribution_chart(self, scan_results):
        """Create a bar chart showing distribution of open ports across scanned IPs"""
        all_ports = []
        for result in scan_results:
            nmap_results = result.get('nmap_results', {})
            ports = nmap_results.get('ports', [])
            for port in ports:
                if port['state'] == 'open':
                    all_ports.append(port['port'])
        
        if not all_ports:
            return None
            
        port_counts = Counter(all_ports)
        ports = list(port_counts.keys())
        counts = list(port_counts.values())
        
        plt.figure(figsize=(12, 6))
        bars = plt.bar(range(len(ports)), counts, color='steelblue', alpha=0.7)
        plt.xlabel('Port Numbers')
        plt.ylabel('Number of Hosts')
        plt.title('Distribution of Open Ports Across Scanned Hosts')
        plt.xticks(range(len(ports)), ports, rotation=45)
        
        # Add value labels on bars
        for bar, count in zip(bars, counts):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    str(count), ha='center', va='bottom')
        
        plt.tight_layout()
        return self._save_plot_to_base64()
    
    def create_abuse_confidence_chart(self, scan_results):
        """Create a pie chart showing distribution of abuse confidence levels"""
        confidence_levels = []
        for result in scan_results:
            abuse_results = result.get('abuseipdb_results', {})
            if 'error' not in abuse_results:
                confidence = abuse_results.get('abuseConfidencePercentage', 0)
                if confidence == 0:
                    confidence_levels.append('Clean (0%)')
                elif confidence < 25:
                    confidence_levels.append('Low Risk (1-24%)')
                elif confidence < 50:
                    confidence_levels.append('Medium Risk (25-49%)')
                elif confidence < 75:
                    confidence_levels.append('High Risk (50-74%)')
                else:
                    confidence_levels.append('Very High Risk (75-100%)')
        
        if not confidence_levels:
            return None
            
        confidence_counts = Counter(confidence_levels)
        labels = list(confidence_counts.keys())
        sizes = list(confidence_counts.values())
        
        colors = ['green', 'yellow', 'orange', 'red', 'darkred']
        colors = colors[:len(labels)]
        
        plt.figure(figsize=(10, 8))
        wedges, texts, autotexts = plt.pie(sizes, labels=labels, colors=colors, 
                                          autopct='%1.1f%%', startangle=90)
        plt.title('Distribution of AbuseIPDB Confidence Levels')
        plt.axis('equal')
        
        return self._save_plot_to_base64()
    
    def create_summary_dashboard(self, scan_results):
        """Create a comprehensive dashboard with multiple charts"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # Chart 1: Port Distribution
        all_ports = []
        for result in scan_results:
            nmap_results = result.get('nmap_results', {})
            ports = nmap_results.get('ports', [])
            for port in ports:
                if port['state'] == 'open':
                    all_ports.append(port['port'])
        
        if all_ports:
            port_counts = Counter(all_ports)
            top_ports = port_counts.most_common(10)
            ports = [str(item[0]) for item in top_ports]
            counts = [item[1] for item in top_ports]
            
            ax1.bar(range(len(ports)), counts, color='steelblue', alpha=0.7)
            ax1.set_xlabel('Port Numbers')
            ax1.set_ylabel('Number of Hosts')
            ax1.set_title('Top 10 Open Ports')
            ax1.set_xticks(range(len(ports)))
            ax1.set_xticklabels(ports, rotation=45)
        else:
            ax1.text(0.5, 0.5, 'No open ports found', ha='center', va='center', transform=ax1.transAxes)
            ax1.set_title('Port Distribution')
        
        # Chart 2: Abuse Confidence
        confidence_levels = []
        for result in scan_results:
            abuse_results = result.get('abuseipdb_results', {})
            if 'error' not in abuse_results:
                confidence = abuse_results.get('abuseConfidencePercentage', 0)
                if confidence == 0:
                    confidence_levels.append('Clean')
                elif confidence < 50:
                    confidence_levels.append('Low-Medium Risk')
                else:
                    confidence_levels.append('High Risk')
        
        if confidence_levels:
            confidence_counts = Counter(confidence_levels)
            labels = list(confidence_counts.keys())
            sizes = list(confidence_counts.values())
            colors = ['green', 'yellow', 'red'][:len(labels)]
            
            ax2.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
            ax2.set_title('Abuse Confidence Distribution')
        else:
            ax2.text(0.5, 0.5, 'No AbuseIPDB data available', ha='center', va='center', transform=ax2.transAxes)
            ax2.set_title('Abuse Confidence Distribution')
        
        # Chart 3: Service Distribution
        all_services = []
        for result in scan_results:
            nmap_results = result.get('nmap_results', {})
            ports = nmap_results.get('ports', [])
            for port in ports:
                if port['state'] == 'open' and port['name']:
                    all_services.append(port['name'])
        
        if all_services:
            service_counts = Counter(all_services)
            top_services = service_counts.most_common(8)
            services = [item[0] for item in top_services]
            counts = [item[1] for item in top_services]
            
            y_pos = np.arange(len(services))
            ax3.barh(y_pos, counts, color='lightcoral', alpha=0.7)
            ax3.set_yticks(y_pos)
            ax3.set_yticklabels(services)
            ax3.set_xlabel('Number of Instances')
            ax3.set_title('Top Services Found')
        else:
            ax3.text(0.5, 0.5, 'No services identified', ha='center', va='center', transform=ax3.transAxes)
            ax3.set_title('Service Distribution')
        
        # Chart 4: Summary Statistics
        total_ips = len(scan_results)
        total_open_ports = len(all_ports)
        high_risk_ips = sum(1 for result in scan_results 
                           if result.get('abuseipdb_results', {}).get('abuseConfidencePercentage', 0) > 50)
        
        stats_text = f"""
        Total IPs Scanned: {total_ips}
        Total Open Ports: {total_open_ports}
        High Risk IPs: {high_risk_ips}
        Unique Services: {len(set(all_services))}
        """
        
        ax4.text(0.1, 0.5, stats_text, ha='left', va='center', transform=ax4.transAxes, 
                fontsize=12, bbox=dict(boxstyle="round,pad=0.3", facecolor="lightblue"))
        ax4.set_title('Summary Statistics')
        ax4.axis('off')
        
        plt.tight_layout()
        return self._save_plot_to_base64()
    
    def _save_plot_to_base64(self):
        """Save the current plot to base64 string for web display"""
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
        buffer.seek(0)
        plot_data = buffer.getvalue()
        buffer.close()
        plt.close()  # Close the figure to free memory
        
        # Convert to base64 for web display
        plot_base64 = base64.b64encode(plot_data).decode('utf-8')
        return f"data:image/png;base64,{plot_base64}"

