# Advanced-Network-Port-Scanner
A feature-rich PHP-based network port scanner with a modern web interface for scanning IP ranges and checking port statuses.
A feature-rich PHP-based network port scanner with a modern web interface for scanning IP ranges and checking port statuses.

Features
🚀 IP Range Scanning: Scan multiple IP addresses in a specified range

🔍 Multi-Port Scanning: Check multiple ports simultaneously (comma-separated list)

📊 Real-time Progress Tracking: Visual progress bar with percentage completion

📋 Results Display: Clean tabular results showing IP, port, status, and server name

📁 CSV Export: Export scan results for further analysis

⏱️ Timeout Control: Configurable connection timeout (default: 1 second)

🛑 Scan Control: Start/stop scanning functionality

🌐 Server Identification: Attempts to resolve hostnames for scanned IPs

📱 Responsive Design: Works on desktop and mobile devices

🎨 Modern UI: Clean, intuitive interface with visual feedback

# Technical Details
Backend: PHP with socket-based port scanning

Frontend: HTML5, CSS3, JavaScript (vanilla, no frameworks)

Validation: IP address format validation

Performance: Chunked processing for better progress reporting

Security: Basic input sanitization and error handling

# Usage
Enter the start and end IP addresses for your scan range

Specify ports to scan (comma-separated, e.g., 80,443,22,21,3389)

Click "Scan Ports" to begin

View results in real-time as they populate

Export to CSV when complete or stop the scan if needed
