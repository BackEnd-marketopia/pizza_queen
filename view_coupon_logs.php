<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>عرض Logs الكوبون</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #4CAF50; }
        .log-entry { background: #252526; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #4CAF50; }
        .log-entry.error { border-left-color: #f44336; }
        .log-entry.warning { border-left-color: #ff9800; }
        .log-time { color: #888; font-size: 12px; }
        .log-message { color: #fff; margin: 5px 0; }
        .log-context { color: #ce9178; font-size: 13px; }
        .icon { font-size: 20px; margin-right: 10px; }
        pre { background: #1e1e1e; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .highlight { background: #3a3d41; padding: 2px 5px; border-radius: 3px; }
        .filter-btn { background: #4CAF50; color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 5px; cursor: pointer; }
        .filter-btn:hover { background: #45a049; }
        .filter-btn.active { background: #2196F3; }
    </style>
</head>
<body>
<div class="container">
    <h1>📋 آخر Logs للكوبون Queen30</h1>
    <p style="color:#888">آخر تحديث: <?php echo date('Y-m-d H:i:s'); ?></p>
    
    <div style="margin:20px 0">
        <button class="filter-btn active" onclick="filterLogs('all')">الكل</button>
        <button class="filter-btn" onclick="filterLogs('🔍')">🔍 Lookup</button>
        <button class="filter-btn" onclick="filterLogs('📋')">📋 Details</button>
        <button class="filter-btn" onclick="filterLogs('👤')">👤 Customer</button>
        <button class="filter-btn" onclick="filterLogs('💰')">💰 Calculation</button>
        <button class="filter-btn" onclick="filterLogs('❌')">❌ Errors</button>
        <button class="filter-btn" onclick="filterLogs('💾')">💾 Final</button>
    </div>
    
    <div id="logs">
    <?php
    $logFile = __DIR__ . '/storage/logs/laravel-' . date('Y-m-d') . '.log';
    
    if (!file_exists($logFile)) {
        $logFile = __DIR__ . '/storage/logs/laravel.log';
    }
    
    if (file_exists($logFile)) {
        $logs = file_get_contents($logFile);
        $lines = explode("\n", $logs);
        
        // Get last 200 lines
        $lines = array_slice($lines, -200);
        
        // Filter lines related to coupon
        $couponLogs = [];
        $currentEntry = '';
        
        foreach ($lines as $line) {
            if (preg_match('/\[(.*?)\]/', $line)) {
                if ($currentEntry && (stripos($currentEntry, 'coupon') !== false || 
                    stripos($currentEntry, 'Queen30') !== false ||
                    preg_match('/🔍|📋|👤|💰|❌|💾|✅/', $currentEntry))) {
                    $couponLogs[] = $currentEntry;
                }
                $currentEntry = $line;
            } else {
                $currentEntry .= "\n" . $line;
            }
        }
        
        // Add last entry
        if ($currentEntry && (stripos($currentEntry, 'coupon') !== false || 
            stripos($currentEntry, 'Queen30') !== false ||
            preg_match('/🔍|📋|👤|💰|❌|💾|✅/', $currentEntry))) {
            $couponLogs[] = $currentEntry;
        }
        
        // Reverse to show newest first
        $couponLogs = array_reverse($couponLogs);
        
        if (empty($couponLogs)) {
            echo '<div class="log-entry warning">';
            echo '<p class="log-message">⚠️ لا توجد logs للكوبون في الملف</p>';
            echo '<p style="color:#888">مسار الملف: ' . $logFile . '</p>';
            echo '<p style="color:#888">اعمل طلب جديد باستخدام الكوبون لتظهر الـ logs</p>';
            echo '</div>';
        } else {
            echo '<p style="color:#4CAF50">✅ تم العثور على ' . count($couponLogs) . ' سطر متعلق بالكوبون</p>';
            
            foreach (array_slice($couponLogs, 0, 50) as $log) {
                $class = 'log-entry';
                if (stripos($log, 'error') !== false || stripos($log, '❌') !== false) {
                    $class .= ' error';
                } elseif (stripos($log, 'warning') !== false || stripos($log, '⚠️') !== false) {
                    $class .= ' warning';
                }
                
                // Extract timestamp
                preg_match('/\[(.*?)\]/', $log, $matches);
                $timestamp = $matches[1] ?? '';
                
                // Extract emoji icon
                $icon = '';
                if (preg_match('/[🔍📋👤💰❌💾✅💵🔒]/u', $log, $iconMatch)) {
                    $icon = $iconMatch[0];
                }
                
                // Highlight important values
                $log = preg_replace('/"discount[^"]*":\s*([0-9.]+)/', '<span class="highlight">"discount": $1</span>', $log);
                $log = preg_replace('/"coupon_discount_amount":\s*([0-9.]+)/', '<span class="highlight" style="background:#f44336;color:#fff">"coupon_discount_amount": $1</span>', $log);
                $log = preg_replace('/"subtotal":\s*([0-9.]+)/', '<span class="highlight">"subtotal": $1</span>', $log);
                $log = preg_replace('/"Queen30"/', '<span class="highlight" style="background:#4CAF50;color:#fff">"Queen30"</span>', $log);
                
                echo '<div class="' . $class . '" data-filter="' . htmlspecialchars($icon) . '">';
                if ($icon) echo '<span class="icon">' . $icon . '</span>';
                echo '<div class="log-time">' . htmlspecialchars($timestamp) . '</div>';
                echo '<pre class="log-context">' . $log . '</pre>';
                echo '</div>';
            }
        }
        
    } else {
        echo '<div class="log-entry error">';
        echo '<p class="log-message">❌ ملف الـ log غير موجود</p>';
        echo '<p style="color:#888">المسار المتوقع: ' . $logFile . '</p>';
        echo '</div>';
    }
    ?>
    </div>
    
    <script>
    function filterLogs(type) {
        const entries = document.querySelectorAll('.log-entry');
        const buttons = document.querySelectorAll('.filter-btn');
        
        buttons.forEach(btn => btn.classList.remove('active'));
        event.target.classList.add('active');
        
        entries.forEach(entry => {
            if (type === 'all') {
                entry.style.display = 'block';
            } else {
                const filter = entry.getAttribute('data-filter');
                entry.style.display = filter === type ? 'block' : 'none';
            }
        });
    }
    </script>
</div>
</body>
</html>
