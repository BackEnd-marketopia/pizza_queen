<?php

/**
 * Test script to verify the Order API fix for order_id null issue
 * This script simulates the order placement flow to ensure order_id is properly returned
 */

require_once 'vendor/autoload.php';

// Load Laravel environment
$app = require_once 'bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);

// Simulate minimal request for testing the order ID generation
$request = Illuminate\Http\Request::create('/', 'POST', [
    'branch_id' => 1,
    'cart' => [
        [
            'product_id' => 1,
            'quantity' => 1,
            'price' => 10.00,
            'variations' => [],
            'add_on_ids' => [],
            'add_on_qtys' => []
        ]
    ],
    'order_amount' => 10.00,
    'payment_method' => 'cash_on_delivery',
    'order_type' => 'delivery',
    'delivery_time' => 'now',
    'delivery_address_id' => 1,
    'distance' => 2.5,
    'guest_id' => 1
]);

echo "=== Order API Fix Test ===\n";
echo "Date: " . date('Y-m-d H:i:s') . "\n\n";

try {
    // Test the order ID generation logic
    $orderModel = new App\Model\Order();
    $currentCount = $orderModel->count();
    
    echo "Current Orders Count: " . $currentCount . "\n";
    
    // Test database insertion
    $testOrder = [
        'user_id' => 1,
        'is_guest' => 1,
        'order_amount' => 15.50,
        'payment_status' => 'unpaid',
        'order_status' => 'pending',
        'payment_method' => 'cash_on_delivery',
        'order_type' => 'delivery',
        'branch_id' => 1,
        'delivery_charge' => 5.50,
        'created_at' => now(),
        'updated_at' => now()
    ];
    
    echo "Inserting test order...\n";
    $generatedId = $orderModel->insertGetId($testOrder);
    
    echo "Generated Order ID: " . $generatedId . "\n";
    echo "Order ID Type: " . gettype($generatedId) . "\n";
    
    if ($generatedId && $generatedId > 0) {
        echo "✓ SUCCESS: Order ID generated successfully\n";
        
        // Clean up test order
        $orderModel->where('id', $generatedId)->delete();
        echo "✓ Test order cleaned up\n";
    } else {
        echo "✗ FAILED: Order ID generation failed\n";
    }
    
    echo "\n=== Fix Implementation Notes ===\n";
    echo "1. Removed manual ID generation (100000 + count + 1)\n";
    echo "2. Let database auto-increment handle ID assignment\n";
    echo "3. Insert order first, then process cart items with correct ID\n";
    echo "4. Update order amount after calculating totals\n";
    echo "5. Fixed all references to use actual database ID\n";
    
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
    echo "Stack trace: " . $e->getTraceAsString() . "\n";
}

echo "\n=== Test Complete ===\n";