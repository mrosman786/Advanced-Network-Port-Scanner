<?php
function validateIp($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP);
}

function scanPort($ip, $port, $timeout = 1) {
    $connection = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    if ($connection) {
        fclose($connection);
        return true;
    }
    return false;
}

function getServerName($ip) {
    $hostname = @gethostbyaddr($ip);
    return ($hostname !== $ip) ? $hostname : "Unknown";
}

function ipRange($start_ip, $end_ip) {
    $start = ip2long($start_ip);
    $end = ip2long($end_ip);
    $range = [];
    for ($ip = $start; $ip <= $end; $ip++) {
        $range[] = long2ip($ip);
    }
    return $range;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    try {
        if (isset($_POST['action']) && $_POST['action'] === 'export_csv') {
            $results = json_decode($_POST['data'], true);
            $filename = 'port_scan_results_' . date('Y-m-d_H-i-s') . '.csv';
            
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            
            $output = fopen('php://output', 'w');
            fputcsv($output, ['IP Address', 'Port', 'Status', 'Server Name']);
            
            foreach ($results as $row) {
                fputcsv($output, $row);
            }
            
            fclose($output);
            exit;
        }
        
        $start_ip = $_POST['start_ip'];
        $end_ip = $_POST['end_ip'];
        $ports = explode(',', $_POST['ports']);
        $current = isset($_POST['current']) ? (int)$_POST['current'] : 0;
        
        // Validate IPs
        if (!validateIp($start_ip) || !validateIp($end_ip)) {
            throw new Exception("Invalid IP address format");
        }
        
        $ip_range = ipRange($start_ip, $end_ip);
        $total_ips = count($ip_range);
        $total_ports = count($ports);
        $total_scans = $total_ips * $total_ports;
        
        $results = [];
        $scanned = 0;
        
        // If this is a progress update, return status
        if (isset($_POST['progress'])) {
            echo json_encode([
                'progress' => $current,
                'total' => $total_scans
            ]);
            exit;
        }
        
        // Process scanning in chunks for better progress reporting
        $chunk_size = 3; // Number of IPs to process per request
        $ip_chunk = array_slice($ip_range, $current, $chunk_size);
        
        foreach ($ip_chunk as $ip) {
            foreach ($ports as $port) {
                $port = trim($port);
                if (!is_numeric($port)) continue;
                
                $serverName = getServerName($ip);
                $status = scanPort($ip, $port) ? "Open" : "Closed";
                
                $results[] = [
                    'ip' => $ip,
                    'port' => $port,
                    'status' => $status,
                    'server' => $serverName
                ];
                
                $scanned++;
            }
        }
        
        echo json_encode([
            'results' => $results,
            'current' => $current + count($ip_chunk),
            'total' => $total_scans,
            'completed' => ($current + count($ip_chunk)) >= $total_ips
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'error' => $e->getMessage()
        ]);
    }
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Advanced Port Scanner</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary-color: #4361ee;
            --primary-dark: #3a56d4;
            --secondary-color: #f8f9fa;
            --text-color: #333;
            --light-gray: #e9ecef;
            --dark-gray: #495057;
            --success-color: #2ecc71;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --border-radius: 8px;
            --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--secondary-color);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }
        
        h1 {
            text-align: center;
            margin-bottom: 30px;
            color: var(--primary-color);
            font-weight: 600;
        }
        
        h2 {
            color: var(--primary-color);
            margin-bottom: 15px;
            text-align: center;
        }
        
        .card {
            background: white;
            padding: 30px;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark-gray);
        }
        
        input[type="text"],
        input[type="number"],
        textarea {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--light-gray);
            border-radius: var(--border-radius);
            font-size: 16px;
            transition: var(--transition);
        }
        
        input[type="text"]:focus,
        input[type="number"]:focus,
        textarea:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.2);
        }
        
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: var(--border-radius);
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
        }
        
        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
        }
        
        .btn-export {
            background-color: var(--success-color);
            margin-left: 10px;
        }
        
        .btn-export:hover {
            background-color: #27ae60;
        }
        
        .btn-stop {
            background-color: var(--danger-color);
            margin-left: 10px;
        }
        
        .btn-stop:hover {
            background-color: #c0392b;
        }
        
        #results {
            margin-top: 30px;
        }
        
        .progress-container {
            margin: 20px 0;
            background-color: var(--light-gray);
            border-radius: var(--border-radius);
            height: 20px;
            overflow: hidden;
        }
        
        .progress-bar {
            height: 100%;
            background-color: var(--primary-color);
            width: 0%;
            transition: width 0.3s ease;
        }
        
        .progress-text {
            text-align: center;
            margin-top: 5px;
            font-size: 14px;
            color: var(--dark-gray);
        }
        
        .loader {
            border: 5px solid var(--light-gray);
            border-top: 5px solid var(--primary-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
            display: none;
        }
        
        .table-container {
            overflow-x: auto;
            margin-top: 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--light-gray);
        }
        
        th {
            background-color: var(--primary-color);
            color: white;
            font-weight: 500;
        }
        
        tr:nth-child(even) {
            background-color: rgba(67, 97, 238, 0.05);
        }
        
        tr:hover {
            background-color: rgba(67, 97, 238, 0.1);
        }
        
        .status-open {
            color: var(--success-color);
            font-weight: 500;
            padding: 4px 8px;
            border-radius: 4px;
            background-color: rgba(46, 204, 113, 0.1);
        }
        
        .status-closed {
            color: var(--danger-color);
            font-weight: 500;
            padding: 4px 8px;
            border-radius: 4px;
            background-color: rgba(231, 76, 60, 0.1);
        }
        
        .error-message {
            color: var(--danger-color);
            background-color: rgba(231, 76, 60, 0.1);
            padding: 15px;
            border-radius: var(--border-radius);
            margin: 20px 0;
            text-align: center;
            border-left: 4px solid var(--danger-color);
        }
        
        .info-message {
            color: var(--primary-color);
            background-color: rgba(67, 97, 238, 0.1);
            padding: 15px;
            border-radius: var(--border-radius);
            margin: 20px 0;
            text-align: center;
            border-left: 4px solid var(--primary-color);
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @media screen and (min-width: 768px) {
            .form-row {
                display: flex;
                gap: 20px;
            }
            
            .form-group {
                flex: 1;
            }
            
            .btn {
                width: auto;
                padding: 12px 30px;
            }
            
            .button-group {
                display: flex;
                justify-content: center;
            }
        }
        
        @media screen and (max-width: 767px) {
            .card {
                padding: 20px;
            }
            
            th, td {
                padding: 8px 10px;
                font-size: 14px;
            }
            
            .button-group {
                display: flex;
                flex-direction: column;
                gap: 10px;
            }
            
            .btn-export, .btn-stop {
                margin-left: 0;
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Advanced Network Port Scanner</h1>
        
        <div class="card">
            <form id="scanForm">
                <div class="form-row">
                    <div class="form-group">
                        <label for="start_ip">Start IP Address</label>
                        <input type="text" id="start_ip" name="start_ip" placeholder="e.g., 192.168.1.1" required>
                        <small class="ip-validation" id="start_ip_validation"></small>
                    </div>
                    
                    <div class="form-group">
                        <label for="end_ip">End IP Address</label>
                        <input type="text" id="end_ip" name="end_ip" placeholder="e.g., 192.168.1.10" required>
                        <small class="ip-validation" id="end_ip_validation"></small>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="ports">Ports to Scan (comma separated)</label>
                    <textarea id="ports" name="ports" placeholder="e.g., 80,443,22,21,3389" required rows="2"></textarea>
                </div>
                
                <div class="button-group">
                    <button type="submit" class="btn" id="scanButton">Scan Ports</button>
                    <button type="button" class="btn btn-export" id="exportButton">Export to CSV</button>
                    <button type="button" class="btn btn-stop" id="stopButton" disabled>Stop Scan</button>
                </div>
            </form>
        </div>
        
        <div class="progress-container" id="progressContainer" style="display: none;">
            <div class="progress-bar" id="progressBar"></div>
            <div class="progress-text" id="progressText">Scanning: 0%</div>
        </div>
        
        <div id="results"></div>
        <div id="loader" class="loader" style="display: none;"></div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('scanForm');
            const results_elem = document.getElementById('results');
            const loader = document.getElementById('loader');
            const progressContainer = document.getElementById('progressContainer');
            const progressBar = document.getElementById('progressBar');
            const progressText = document.getElementById('progressText');
            const scanButton = document.getElementById('scanButton');
            const exportButton = document.getElementById('exportButton');
            const stopButton = document.getElementById('stopButton');
            
            let scanInProgress = false;
            let currentScanData = [];
            let allResults = []; // Store all accumulated results
     
            
            form.addEventListener('submit', function(event) {
                event.preventDefault();
                startScan();
            });
            
            stopButton.addEventListener('click', function() {
                if (scanInProgress) {
                    scanInProgress = false;
                    stopButton.disabled = true;
                    scanButton.disabled = false;
                    showInfo('Scan stopped by user');
                }
            });
            
            exportButton.addEventListener('click', function() {
                if (allResults.length === 0) {
                    showError('No data to export');
                    return;
                }
                exportToCSV(allResults);
            });
            
            function startScan() {
                // Clear previous results
                results_elem.innerHTML = '';
                allResults = [];
                currentScanData = [];
                
                // Show loader and progress
                loader.style.display = 'block';
                progressContainer.style.display = 'block';
                progressBar.style.width = '0%';
                progressText.textContent = 'Scanning: 0%';
                
                // Disable form and enable stop button
                scanButton.disabled = true;
                stopButton.disabled = false;
                exportButton.disabled = true;
                scanInProgress = true;
                
                // Start scanning
                scanPorts(0);
            }
            
            function scanPorts(current) {
                if (!scanInProgress) return;
                
                const formData = new FormData(form);
                formData.append('current', current);
                
                fetch("", {
                    method: "POST",
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.error) {
                        throw new Error(data.error);
                    }
                    
                    // Update progress
                    const progress = Math.round((data.current / data.total) * 100);
                    progressBar.style.width = progress + '%';
                    progressText.textContent = `Scanning: ${progress}% (${data.current} of ${data.total})`;
                    
                    // Accumulate results
                    if (data.results && data.results.length > 0) {
                        allResults = [...allResults, ...data.results];
                        displayResults(allResults);
                    }
                    
                    // If completed, finish up
                    if (data.completed) {
                        completeScan();
                    } else {
                        // Continue scanning
                        setTimeout(() => scanPorts(data.current), 40);
                    }
                })
                .catch(error => {
                    completeScan(error.message);
                });
            }
            
            function completeScan(error = null) {
                loader.style.display = 'none';
                scanInProgress = false;
                scanButton.disabled = false;
                stopButton.disabled = true;
                
                if (error) {
                    showError(error);
                    return;
                }
                
                if (allResults.length === 0) {
                    showInfo('No results found');
                    exportButton.disabled = true;
                    return;
                }
                
                exportButton.disabled = false;
            }
            
            function displayResults(results) {
                let html = `
                    <h2>Scan Results</h2>
                    <div class="info-message">
                        Found ${results.filter(r => r.status === 'Open').length} open ports out of ${results.length} scanned
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Port</th>
                                    <th>Status</th>
                                    <th>Server Name</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                results.forEach(result => {
                    const statusClass = result.status.toLowerCase() === 'open' ? 'status-open' : 'status-closed';
                    html += `
                        <tr>
                            <td>${result.ip}</td>
                            <td>${result.port}</td>
                            <td><span class="${statusClass}">${result.status}</span></td>
                            <td>${result.server}</td>
                        </tr>
                    `;
                });
                
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
                
                results_elem.innerHTML = html;
            }
            
            function exportToCSV(data) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '';
                
                const inputAction = document.createElement('input');
                inputAction.type = 'hidden';
                inputAction.name = 'action';
                inputAction.value = 'export_csv';
                form.appendChild(inputAction);
                
                const inputData = document.createElement('input');
                inputData.type = 'hidden';
                inputData.name = 'data';
                inputData.value = JSON.stringify(data);
                form.appendChild(inputData);
                
                document.body.appendChild(form);
                form.submit();
                document.body.removeChild(form);
            }
            
            function showError(message) {
                results_elem.innerHTML = `<div class="error-message">${message}</div>`;
            }
            
            function showInfo(message) {
                results_elem.innerHTML = `<div class="info-message">${message}</div>`;
            }
        });
    </script>
</body>
</html>
