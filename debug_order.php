<?php
require 'vendor/autoload.php';

$app = require 'bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);

// Initialize Laravel application
$kernel->bootstrap();

// Alternative method to get database connection
use Illuminate\Support\Facades\DB;

try {
    $order = \App\Model\Order::find(100209);
    if ($order) {
        echo "Order 100209 details:\n";
        echo "Order Amount: " . $order->order_amount . "\n";
        echo "User ID: " . $order->user_id . "\n";
        echo "Created At: " . $order->created_at . "\n\n";
        
        $orderDetails = \App\Model\OrderDetail::where('order_id', 100209)->get();
        echo "Number of Order Details: " . $orderDetails->count() . "\n\n";
        
        foreach ($orderDetails as $i => $detail) {
            $productDetails = json_decode($detail->product_details, true);
            $productName = $productDetails ? $productDetails['name'] : 'Unknown';
            
            echo ($i + 1) . ". Product: $productName\n";
            echo "   Product ID: $detail->product_id\n";
            echo "   Price: $detail->price\n";
            echo "   Quantity: $detail->quantity\n";
            echo "   Total Price: " . ($detail->price * $detail->quantity) . "\n";
            echo "   Is Free: " . ($detail->is_free ? 'Yes' : 'No') . "\n";
            echo "   Add-on IDs: " . ($detail->add_on_ids ?? 'None') . "\n";
            echo "   Add-on Quantities: " . ($detail->add_on_qtys ?? 'None') . "\n";
            echo "   Variations: " . ($detail->variations ?? 'None') . "\n\n";
        }
    } else {
        echo "Order 100209 not found\n";
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}