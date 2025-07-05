from flask import Blueprint, request, jsonify, send_file
from src.security_analyzer import SecurityAnalyzer, SecurityDataVisualizer
from src.pdf_generator import SecurityReportGenerator
import tempfile
import os

security_bp = Blueprint('security', __name__)

# Initialize analyzers
analyzer = SecurityAnalyzer()
visualizer = SecurityDataVisualizer()
report_generator = SecurityReportGenerator()

@security_bp.route('/scan/automated', methods=['POST'])
def automated_scan():
    """Perform automated scan on target IP or range"""
    try:
        data = request.get_json()
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target IP or range is required'}), 400
        
        results = analyzer.perform_automated_scan(target)
        return jsonify({'success': True, 'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/scan/log', methods=['POST'])
def log_analysis():
    """Analyze log file content"""
    try:
        data = request.get_json()
        log_content = data.get('log_content')
        
        if not log_content:
            return jsonify({'error': 'Log content is required'}), 400
        
        results = analyzer.analyze_log_file_content(log_content)
        return jsonify({'success': True, 'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/visualizations/port-distribution', methods=['POST'])
def port_distribution_chart():
    """Generate port distribution chart"""
    try:
        data = request.get_json()
        scan_results = data.get('scan_results', [])
        
        chart_data = visualizer.create_port_distribution_chart(scan_results)
        
        if chart_data:
            return jsonify({'success': True, 'chart_data': chart_data})
        else:
            return jsonify({'success': False, 'message': 'No data available for visualization'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/visualizations/abuse-confidence', methods=['POST'])
def abuse_confidence_chart():
    """Generate abuse confidence chart"""
    try:
        data = request.get_json()
        scan_results = data.get('scan_results', [])
        
        chart_data = visualizer.create_abuse_confidence_chart(scan_results)
        
        if chart_data:
            return jsonify({'success': True, 'chart_data': chart_data})
        else:
            return jsonify({'success': False, 'message': 'No data available for visualization'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/visualizations/summary-dashboard', methods=['POST'])
def summary_dashboard():
    """Generate summary dashboard"""
    try:
        data = request.get_json()
        scan_results = data.get('scan_results', [])
        
        chart_data = visualizer.create_summary_dashboard(scan_results)
        
        if chart_data:
            return jsonify({'success': True, 'chart_data': chart_data})
        else:
            return jsonify({'success': False, 'message': 'No data available for visualization'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/report/generate', methods=['POST'])
def generate_report():
    """Generate PDF report"""
    try:
        data = request.get_json()
        scan_results = data.get('scan_results', [])
        
        if not scan_results:
            return jsonify({'error': 'Scan results are required'}), 400
        
        # Generate visualizations for the report
        visualizations = {}
        visualizations['port_distribution'] = visualizer.create_port_distribution_chart(scan_results)
        visualizations['abuse_confidence'] = visualizer.create_abuse_confidence_chart(scan_results)
        visualizations['summary_dashboard'] = visualizer.create_summary_dashboard(scan_results)
        
        # Create temporary file for PDF
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Generate PDF report
        output_file = report_generator.generate_report(scan_results, visualizations, temp_file.name)
        
        # Return the PDF file
        return send_file(output_file, as_attachment=True, download_name='security_report.pdf', mimetype='application/pdf')
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'Security Analysis Tool'})

