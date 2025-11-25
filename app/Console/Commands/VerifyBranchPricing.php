<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Model\Order;
use App\Model\OrderDetail;
use App\Model\ProductByBranch;
use App\Model\Product;
use Illuminate\Support\Facades\DB;

class VerifyBranchPricing extends Command
{
    protected $signature = 'orders:verify-branch-pricing {--order-id=} {--recent=10}';
    protected $description = 'Verify that orders have correct branch-specific pricing and tax data';

    public function handle()
    {
        $this->info('🔍 Verifying Branch Pricing in Orders...');
        
        // Get orders to check
        if ($orderId = $this->option('order-id')) {
            $orders = Order::where('id', $orderId)->with(['details', 'branch'])->get();
        } else {
            $recentCount = $this->option('recent') ?? 10;
            $orders = Order::with(['details', 'branch'])
                          ->whereNotNull('branch_id')
                          ->orderBy('created_at', 'desc')
                          ->take($recentCount)
                          ->get();
        }

        if ($orders->isEmpty()) {
            $this->error('❌ No orders found to verify');
            return;
        }

        $this->info("📊 Checking {$orders->count()} orders...\n");

        $issues = [];
        $verified = 0;

        foreach ($orders as $order) {
            $branchName = $order->branch ? $order->branch->name : 'N/A';
            $this->info("Order ID: {$order->id} | Branch: {$branchName} | Date: {$order->created_at}");
            
            $orderIssues = [];
            
            foreach ($order->details as $detail) {
                $product = Product::find($detail->product_id);
                if (!$product) {
                    $orderIssues[] = "Product {$detail->product_id} not found";
                    continue;
                }

                $branchProduct = ProductByBranch::where([
                    'product_id' => $detail->product_id,
                    'branch_id' => $order->branch_id
                ])->first();

                // Check if branch-specific price was used
                $expectedPrice = $branchProduct ? $branchProduct->price : $product->price;
                $savedPrice = $detail->price;

                if (abs($expectedPrice - $savedPrice) > 0.01) {
                    $orderIssues[] = "❌ Product {$product->name}: Expected price {$expectedPrice}, but saved {$savedPrice}";
                } else {
                    $this->line("  ✅ {$product->name}: Price correct ({$savedPrice})");
                }

                // Check tax calculation
                if ($product->tax_type === 'percent') {
                    $expectedTax = ($savedPrice / 100) * $product->tax;
                } else {
                    $expectedTax = $product->tax;
                }

                if (abs($expectedTax - $detail->tax_amount) > 0.01) {
                    $orderIssues[] = "❌ Product {$product->name}: Expected tax {$expectedTax}, but saved {$detail->tax_amount}";
                } else {
                    $this->line("  ✅ {$product->name}: Tax correct ({$detail->tax_amount})");
                }
            }

            if (empty($orderIssues)) {
                $this->info("✅ Order {$order->id}: All pricing and tax data correct");
                $verified++;
            } else {
                $this->error("❌ Order {$order->id}: Issues found:");
                foreach ($orderIssues as $issue) {
                    $this->line("    {$issue}");
                }
                $issues[] = [
                    'order_id' => $order->id,
                    'issues' => $orderIssues
                ];
            }

            $this->line("");
        }

        // Summary
        $this->info("📈 SUMMARY:");
        $this->info("✅ Verified orders: {$verified}");
        $this->info("❌ Orders with issues: " . count($issues));

        if (!empty($issues)) {
            $this->info("\n🔧 Suggested actions:");
            $this->info("1. Check recent orders to ensure branch pricing is working");
            $this->info("2. Verify ProductByBranch data is correctly configured");
            $this->info("3. Check POS controller logging for pricing calculations");
        }

        return 0;
    }
}