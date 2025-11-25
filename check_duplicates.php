<?php
// Check for duplicate order details in recent orders
$host = 'localhost';
$username = 'root'; 
$password = 'mysql';
$database = 'pizza_queen';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$database", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    echo "Analyzing duplicate order details patterns...\n\n";
    
    // Check for orders where the same product appears multiple times (not including free products)
    $stmt = $pdo->prepare("
        SELECT 
            order_id,
            product_id,
            COUNT(*) as duplicate_count,
            GROUP_CONCAT(is_free ORDER BY created_at SEPARATOR ',') as is_free_pattern,
            GROUP_CONCAT(created_at ORDER BY created_at SEPARATOR ',') as creation_times
        FROM order_details 
        WHERE order_id IN (SELECT id FROM orders WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY))
        GROUP BY order_id, product_id 
        HAVING duplicate_count > 1
        ORDER BY order_id DESC
        LIMIT 20
    ");
    $stmt->execute();
    $duplicates = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (!empty($duplicates)) {
        echo "Found duplicate product entries:\n";
        foreach ($duplicates as $dup) {
            echo "Order ID: " . $dup['order_id'] . "\n";
            echo "Product ID: " . $dup['product_id'] . "\n"; 
            echo "Appears: " . $dup['duplicate_count'] . " times\n";
            echo "Is Free Pattern: " . $dup['is_free_pattern'] . "\n";
            echo "Creation Times: " . $dup['creation_times'] . "\n\n";
        }
        
        // Analyze the first duplicate order in detail
        $firstOrder = $duplicates[0]['order_id'];
        echo "Detailed analysis of Order $firstOrder:\n\n";
        
        $detailStmt = $pdo->prepare("
            SELECT *, 
                   product_details,
                   free_for_product_id,
                   add_on_ids,
                   add_on_qtys,
                   created_at
            FROM order_details 
            WHERE order_id = ?
            ORDER BY created_at ASC, is_free ASC
        ");
        $detailStmt->execute([$firstOrder]);
        $details = $detailStmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($details as $i => $detail) {
            $productData = json_decode($detail['product_details'], true);
            echo ($i + 1) . ". Product: " . ($productData['name'] ?? 'Unknown') . "\n";
            echo "   Product ID: " . $detail['product_id'] . "\n";
            echo "   Is Free: " . ($detail['is_free'] ? 'Yes' : 'No') . "\n";
            echo "   Free For Product ID: " . ($detail['free_for_product_id'] ?? 'None') . "\n";
            echo "   Price: " . $detail['price'] . "\n";
            echo "   Quantity: " . $detail['quantity'] . "\n";
            echo "   Add-on IDs: " . ($detail['add_on_ids'] ?? 'None') . "\n";
            echo "   Add-on Qtys: " . ($detail['add_on_qtys'] ?? 'None') . "\n";
            echo "   Created At: " . $detail['created_at'] . "\n\n";
        }
    } else {
        echo "No duplicate product entries found in recent orders.\n";
        echo "This suggests the duplication issue might be resolved.\n";
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage() . "\n";
}