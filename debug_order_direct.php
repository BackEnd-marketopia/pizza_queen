<?php
// Direct database query without Laravel framework overhead
$host = 'localhost';
$username = 'root'; 
$password = 'mysql'; // AMPPS default password
$database = 'pizza_queen';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$database", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    echo "Checking latest orders and their details...\n\n";
    
    // Get latest 5 orders
    $orderStmt = $pdo->prepare("
        SELECT o.id, o.order_amount, o.user_id, o.created_at, COUNT(od.id) as detail_count
        FROM orders o 
        LEFT JOIN order_details od ON o.id = od.order_id 
        GROUP BY o.id 
        ORDER BY o.id DESC 
        LIMIT 5
    ");
    $orderStmt->execute();
    $orders = $orderStmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "Latest 5 Orders with details count:\n";
    foreach ($orders as $order) {
        echo "Order ID: " . $order['id'] . " - Amount: " . $order['order_amount'] . " - Details: " . $order['detail_count'] . " - Created: " . $order['created_at'] . "\n";
    }
    
    echo "\nDetailed analysis of latest order:\n\n";
    if (!empty($orders)) {
        $latestOrderId = $orders[0]['id'];
        
        // Get order details for latest order
        $detailsStmt = $pdo->prepare("SELECT * FROM order_details WHERE order_id = ? ORDER BY is_free ASC, created_at ASC");
        $detailsStmt->execute([$latestOrderId]);
        $orderDetails = $detailsStmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo "Order $latestOrderId has " . count($orderDetails) . " details:\n\n";
        
        foreach ($orderDetails as $i => $detail) {
            $productDetails = json_decode($detail['product_details'], true);
            $productName = $productDetails ? $productDetails['name'] : 'Unknown';
            
            echo ($i + 1) . ". Product: $productName\n";
            echo "   Product ID: " . $detail['product_id'] . "\n";
            echo "   Price: " . $detail['price'] . "\n";
            echo "   Quantity: " . $detail['quantity'] . "\n";
            echo "   Is Free: " . ($detail['is_free'] ? 'Yes' : 'No') . "\n";
            echo "   Free For Product ID: " . ($detail['free_for_product_id'] ?? 'None') . "\n";
            echo "   Add-on IDs: " . ($detail['add_on_ids'] ?? 'None') . "\n";
            echo "   Created At: " . $detail['created_at'] . "\n\n";
        }
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage() . "\n";
}