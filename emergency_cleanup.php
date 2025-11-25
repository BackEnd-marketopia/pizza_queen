<?php
require_once 'vendor/autoload.php';

try {
    // حذف الطلبات الفاسدة
    $pdo = new PDO('mysql:host=localhost;dbname=u850921305_pizza_queen', 'u850921305_pizza_queen', '8C7*RL>gY3');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // البحث عن الطلبات التي تحتوي على أكثر من 10 منتجات
    $stmt = $pdo->prepare("
        SELECT o.id, COUNT(od.id) as product_count, o.created_at 
        FROM orders o 
        JOIN order_details od ON o.id = od.order_id 
        WHERE o.created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
        GROUP BY o.id 
        HAVING product_count > 10
        ORDER BY o.created_at DESC
    ");
    $stmt->execute();
    $corruptedOrders = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "🔍 Found corrupted orders: " . count($corruptedOrders) . "\n";
    
    foreach ($corruptedOrders as $order) {
        echo "   Order #{$order['id']}: {$order['product_count']} products ({$order['created_at']})\n";
    }
    
    if (!empty($corruptedOrders)) {
        $orderIds = array_column($corruptedOrders, 'id');
        $placeholders = str_repeat('?,', count($orderIds) - 1) . '?';
        
        // حذف تفاصيل الطلبات الفاسدة
        $stmt = $pdo->prepare("DELETE FROM order_details WHERE order_id IN ($placeholders)");
        $stmt->execute($orderIds);
        echo "✅ Deleted order details\n";
        
        // تحديث حالة الطلبات
        $stmt = $pdo->prepare("UPDATE orders SET order_status = 'cancelled_cleanup' WHERE id IN ($placeholders)");
        $stmt->execute($orderIds);
        echo "✅ Updated order status\n";
    }
    
    // التحقق من البيانات اليتيمة
    $stmt = $pdo->prepare("
        SELECT od.order_id, COUNT(od.id) as details_count
        FROM order_details od 
        LEFT JOIN orders o ON od.order_id = o.id 
        WHERE o.id IS NULL
        GROUP BY od.order_id
    ");
    $stmt->execute();
    $orphaned = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (!empty($orphaned)) {
        echo "🧹 Found orphaned order details: " . count($orphaned) . "\n";
        
        foreach ($orphaned as $orphan) {
            echo "   Order ID #{$orphan['order_id']}: {$orphan['details_count']} orphaned details\n";
        }
        
        // حذف البيانات اليتيمة
        $stmt = $pdo->prepare("
            DELETE od FROM order_details od 
            LEFT JOIN orders o ON od.order_id = o.id 
            WHERE o.id IS NULL
        ");
        $stmt->execute();
        echo "✅ Cleaned orphaned details\n";
    }
    
    // البحث عن الطلب 100209 تحديداً
    $stmt = $pdo->prepare("
        SELECT od.*, p.name as product_name 
        FROM order_details od 
        LEFT JOIN products p ON od.product_id = p.id 
        WHERE od.order_id = 100209
        ORDER BY od.id
    ");
    $stmt->execute();
    $orderDetails = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (!empty($orderDetails)) {
        echo "\n🔍 Order 100209 has " . count($orderDetails) . " products:\n";
        foreach ($orderDetails as $detail) {
            echo "   - Product #{$detail['product_id']} ({$detail['product_name']}) - Free: {$detail['is_free']} - Price: {$detail['price']}\n";
        }
        
        // حذف هذا الطلب
        $stmt = $pdo->prepare("DELETE FROM order_details WHERE order_id = 100209");
        $stmt->execute();
        echo "✅ Cleaned order 100209\n";
        
        $stmt = $pdo->prepare("UPDATE orders SET order_status = 'cancelled_cleanup' WHERE id = 100209");
        $stmt->execute();
        echo "✅ Cancelled order 100209\n";
    }
    
    echo "\n🎯 Database cleaned! Ready for testing.\n";
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
?>