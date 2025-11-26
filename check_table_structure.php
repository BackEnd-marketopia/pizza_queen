<?php
require_once 'vendor/autoload.php';

$app = require_once 'bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);
$app->detectEnvironment(function() { return 'live'; });
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use Illuminate\Support\Facades\DB;

try {
    echo "🔍 Checking order_details table structure...\n";
    
    // فحص structure عمود variant
    $columns = DB::select("DESCRIBE order_details");
    
    foreach ($columns as $column) {
        if (in_array($column->Field, ['variant', 'variation', 'product_details', 'free_product'])) {
            echo "Column: {$column->Field}\n";
            echo "   Type: {$column->Type}\n";
            echo "   Null: {$column->Null}\n";
            echo "   Key: {$column->Key}\n";
            echo "   Default: {$column->Default}\n";
            echo "   Extra: {$column->Extra}\n\n";
        }
    }
    
    echo "✅ Done! Check the variant column type.\n";
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
?>