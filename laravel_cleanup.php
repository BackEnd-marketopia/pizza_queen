<?php
// تنظيف قاعدة البيانات من Laravel
require_once __DIR__.'/vendor/autoload.php';

$app = require_once __DIR__.'/bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);

// تحديد البيئة
$app->detectEnvironment(function() {
    return 'live';
});

$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use Illuminate\Support\Facades\DB;

try {
    echo "🔍 Searching for corrupted orders...\n";
    
    // البحث عن الطلبات الفاسدة
    $corruptedOrders = DB::select("
        SELECT o.id, COUNT(od.id) as product_count, o.created_at 
        FROM orders o 
        JOIN order_details od ON o.id = od.order_id 
        WHERE o.created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
        GROUP BY o.id 
        HAVING product_count > 10
        ORDER BY o.created_at DESC
    ");
    
    echo "Found " . count($corruptedOrders) . " corrupted orders\n";
    
    foreach ($corruptedOrders as $order) {
        echo "   Order #{$order->id}: {$order->product_count} products ({$order->created_at})\n";
    }
    
    if (!empty($corruptedOrders)) {
        $orderIds = array_column($corruptedOrders, 'id');
        
        // حذف تفاصيل الطلبات الفاسدة
        $deleted = DB::table('order_details')->whereIn('order_id', $orderIds)->delete();
        echo "✅ Deleted {$deleted} order details\n";
        
        // تحديث حالة الطلبات
        $updated = DB::table('orders')->whereIn('id', $orderIds)->update([
            'order_status' => 'cancelled_cleanup',
            'updated_at' => now()
        ]);
        echo "✅ Updated {$updated} orders status\n";
    }
    
    // التحقق من الطلب 100209 تحديداً
    $orderDetails = DB::select("
        SELECT od.*, p.name as product_name 
        FROM order_details od 
        LEFT JOIN products p ON od.product_id = p.id 
        WHERE od.order_id = 100209
        ORDER BY od.id
    ");
    
    if (!empty($orderDetails)) {
        echo "\n🔍 Order 100209 has " . count($orderDetails) . " products:\n";
        foreach ($orderDetails as $detail) {
            echo "   - Product #{$detail->product_id} ({$detail->product_name}) - Free: {$detail->is_free} - Price: {$detail->price}\n";
        }
        
        // حذف هذا الطلب
        $deleted = DB::table('order_details')->where('order_id', 100209)->delete();
        echo "✅ Deleted {$deleted} items from order 100209\n";
        
        $updated = DB::table('orders')->where('id', 100209)->update([
            'order_status' => 'cancelled_cleanup',
            'updated_at' => now()
        ]);
        echo "✅ Cancelled order 100209\n";
    } else {
        echo "\n✅ Order 100209 is already clean\n";
    }
    
    echo "\n🎯 Database cleaned! Ready for testing.\n";
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}
?>