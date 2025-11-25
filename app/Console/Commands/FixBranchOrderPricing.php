<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Model\Order;
use App\Model\OrderDetail;
use App\Model\ProductByBranch;
use App\Model\Product;
use App\CentralLogics\Helpers;
use Illuminate\Support\Facades\DB;

class FixBranchOrderPricing extends Command
{
    protected $signature = 'orders:fix-branch-pricing {--order-id=} {--dry-run} {--confirm}';
    protected $description = 'Fix orders that may have incorrect branch pricing data';

    public function handle()
    {
        $this->info('🔧 Fixing Branch Order Pricing...');
        
        if (!$this->option('confirm') && !$this->option('dry-run')) {
            $this->error('⚠️  This command will modify order data. Use --dry-run to preview changes or --confirm to execute.');
            return 1;
        }

        $isDryRun = $this->option('dry-run');
        
        if ($isDryRun) {
            $this->info('🔍 DRY RUN MODE - No changes will be made');
        }

        // Get orders to fix
        if ($orderId = $this->option('order-id')) {
            $orders = Order::where('id', $orderId)->with(['details', 'branch'])->get();
        } else {
            // Get recent orders that might have pricing issues
            $orders = Order::with(['details', 'branch'])
                          ->whereNotNull('branch_id')
                          ->where('created_at', '>', now()->subDays(30)) // Last 30 days
                          ->get();
        }

        if ($orders->isEmpty()) {
            $this->error('❌ No orders found to fix');
            return 1;
        }

        $this->info("📊 Checking {$orders->count()} orders...\n");

        $fixed = 0;
        $skipped = 0;

        foreach ($orders as $order) {
            $branchName = $order->branch ? $order->branch->name : 'N/A';
            $this->info("Processing Order ID: {$order->id} | Branch: {$branchName}");
            
            $hasChanges = false;
            
            foreach ($order->details as $detail) {
                $product = Product::find($detail->product_id);
                if (!$product) {
                    $this->line("  ⚠️  Product {$detail->product_id} not found - skipping");
                    continue;
                }

                $branchProduct = ProductByBranch::where([
                    'product_id' => $detail->product_id,
                    'branch_id' => $order->branch_id
                ])->first();

                // Check if we should use branch price
                if ($branchProduct && abs($branchProduct->price - $detail->price) > 0.01) {
                    $oldPrice = $detail->price;
                    $newPrice = $branchProduct->price;
                    
                    // Recalculate tax based on new price
                    $newTaxAmount = Helpers::tax_calculate($product, $newPrice);
                    $oldTaxAmount = $detail->tax_amount;
                    
                    // Recalculate discount if any
                    $discountData = [
                        'discount_type' => $branchProduct->discount_type,
                        'discount' => $branchProduct->discount
                    ];
                    $newDiscount = Helpers::discount_calculate($discountData, $newPrice);
                    $oldDiscount = $detail->discount_on_product;

                    $this->line("  🔄 {$product->name}:");
                    $this->line("    Price: {$oldPrice} → {$newPrice}");
                    $this->line("    Tax: {$oldTaxAmount} → {$newTaxAmount}");
                    $this->line("    Discount: {$oldDiscount} → {$newDiscount}");

                    if (!$isDryRun) {
                        $detail->update([
                            'price' => $newPrice,
                            'tax_amount' => $newTaxAmount,
                            'discount_on_product' => $newDiscount
                        ]);
                    }
                    
                    $hasChanges = true;
                } else {
                    $this->line("  ✅ {$product->name}: No changes needed");
                }
            }

            if ($hasChanges) {
                if (!$isDryRun) {
                    // Recalculate order totals
                    $this->recalculateOrderTotals($order);
                    $this->info("  ✅ Order {$order->id} updated successfully");
                } else {
                    $this->info("  📝 Order {$order->id} would be updated");
                }
                $fixed++;
            } else {
                $this->line("  ⏭️  Order {$order->id}: No changes needed");
                $skipped++;
            }

            $this->line("");
        }

        // Summary
        $this->info("📈 SUMMARY:");
        if ($isDryRun) {
            $this->info("📝 Orders that would be fixed: {$fixed}");
        } else {
            $this->info("✅ Orders fixed: {$fixed}");
        }
        $this->info("⏭️  Orders skipped: {$skipped}");

        return 0;
    }

    private function recalculateOrderTotals($order)
    {
        $totalAmount = 0;
        $totalTax = 0;
        
        foreach ($order->details as $detail) {
            $itemTotal = ($detail->price - $detail->discount_on_product) * $detail->quantity;
            $itemTax = $detail->tax_amount * $detail->quantity;
            $totalAmount += $itemTotal;
            $totalTax += $itemTax;
        }
        
        $order->update([
            'order_amount' => $totalAmount + $totalTax + $order->delivery_charge + $order->total_add_on_tax
        ]);
    }
}