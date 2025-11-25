<?php

// Check database status
echo "=== DATABASE STATUS CHECK ===\n\n";

try {
    $pdo = new PDO('mysql:host=localhost;dbname=u850921305_pizza_queen', 'root', 'mysql');
    
    // Get last order
    $stmt = $pdo->query("SELECT id, user_id, order_amount, created_at FROM orders ORDER BY id DESC LIMIT 1");
    $lastOrder = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($lastOrder) {
        echo "📋 Last Order:\n";
        echo "- ID: " . $lastOrder['id'] . "\n";
        echo "- Amount: " . $lastOrder['order_amount'] . "\n";
        echo "- Created: " . $lastOrder['created_at'] . "\n\n";
        
        // Get order details
        $stmt = $pdo->prepare("SELECT product_id, is_free, price, quantity FROM order_details WHERE order_id = ? ORDER BY id");
        $stmt->execute([$lastOrder['id']]);
        $details = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo "📦 Order Details (" . count($details) . " products):\n";
        foreach($details as $detail) {
            echo "- Product ID: " . $detail['product_id'] . 
                 ", is_free: " . ($detail['is_free'] ? 'true' : 'false') . 
                 ", price: " . $detail['price'] . 
                 ", qty: " . $detail['quantity'] . "\n";
        }
    } else {
        echo "No orders found\n";
    }
    
} catch (Exception $e) {
    echo "Database error: " . $e->getMessage() . "\n";
    echo "Using different connection...\n";
    
    // Try XAMPP default
    try {
        $pdo = new PDO('mysql:host=localhost;dbname=pizza_queen_db', 'root', '');
        echo "Connected with empty password\n";
    } catch (Exception $e2) {
        echo "Could not connect: " . $e2->getMessage() . "\n";
    }
}

echo "\n=== STATUS COMPLETE ===\n";