<?php
echo "Testing database connection...\n";
try {
    $pdo = new PDO('mysql:host=localhost;dbname=u850921305_pizza_queen', 'u850921305_pizza_queen', '8C7*RL>gY3');
    echo "✅ Connected successfully!\n";
    
    // اختبار استعلام بسيط
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM orders");
    $result = $stmt->fetch();
    echo "✅ Orders table accessible. Total orders: " . $result['count'] . "\n";
    
} catch(Exception $e) {
    echo "❌ Connection failed: " . $e->getMessage() . "\n";
}
?>