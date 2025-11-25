<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Model\Order;
use App\Model\OrderDetail;
use App\Model\ProductByBranch;
use App\Model\Product;
use App\CentralLogics\Helpers;

class VerifyOrderDataConsistency extends Command
{
    protected $signature = 'orders:verify-data-consistency {--order-id=} {--recent=5}';
    protected $description = 'Verify that order list and order details show the same data and use branch-specific pricing';

    public function handle()
    {
        $this->info('🔍 Verifying Order Data Consistency...');
        
        // Get orders to check
        if ($orderId = $this->option('order-id')) {
            $orders = Order::where('id', $orderId)->with(['details', 'branch'])->get();
        } else {
            $recentCount = $this->option('recent') ?? 5;
            $orders = Order::with(['details', 'branch'])
                          ->whereNotNull('branch_id')
                          ->orderBy('created_at', 'desc')
                          ->take($recentCount)
                          ->get();
        }

        if ($orders->isEmpty()) {
            $this->error('❌ No orders found to verify');
            return 1;
        }

        $this->info("📊 Checking {$orders->count()} orders...\n");

        foreach ($orders as $order) {
            $this->info("🔍 Order ID: {$order->id} | Branch: " . ($order->branch ? $order->branch->name : 'N/A'));
            
            // 1. Check order_amount consistency
            $storedOrderAmount = $order->order_amount;
            $this->line("   💾 Stored order_amount: " . Helpers::set_symbol($storedOrderAmount));
            
            // 2. Calculate order amount from details (manual verification)
            $calculatedSubtotal = 0;
            $calculatedTax = 0;
            $calculatedDiscount = 0;
            $calculatedAddonCost = 0;
            $calculatedAddonTax = 0;
            
            foreach ($order->details as $detail) {
                $itemAmount = $detail->price * $detail->quantity;
                $itemDiscount = $detail->discount_on_product * $detail->quantity;
                $itemTax = $detail->tax_amount * $detail->quantity;
                $itemAddonTax = $detail->add_on_tax_amount;
                
                $calculatedSubtotal += $itemAmount;
                $calculatedDiscount += $itemDiscount;
                $calculatedTax += $itemTax;
                $calculatedAddonTax += $itemAddonTax;
                
                // Check addon prices
                $addOnPrices = json_decode($detail->add_on_prices, true) ?? [];
                $addOnQtys = json_decode($detail->add_on_qtys, true) ?? [];
                
                for ($i = 0; $i < count($addOnPrices); $i++) {
                    $qty = isset($addOnQtys[$i]) ? $addOnQtys[$i] : 1;
                    $calculatedAddonCost += $addOnPrices[$i] * $qty;
                }
                
                // Verify this item uses branch pricing
                $product = Product::find($detail->product_id);
                $branchProduct = ProductByBranch::where([
                    'product_id' => $detail->product_id,
                    'branch_id' => $order->branch_id
                ])->first();
                
                if ($branchProduct) {
                    if (abs($branchProduct->price - $detail->price) > 0.01) {
                        $this->error("   ❌ Product {$product->name}: Uses main price {$detail->price} instead of branch price {$branchProduct->price}");
                    } else {
                        $this->line("   ✅ Product {$product->name}: Correct branch price {$detail->price}");
                    }
                } else {
                    $this->line("   ⚠️  Product {$product->name}: No branch-specific pricing found");
                }
            }
            
            // Calculate expected order amount
            $netAmount = $calculatedSubtotal - $calculatedDiscount + $calculatedTax + $calculatedAddonCost + $calculatedAddonTax;
            $expectedOrderAmount = $netAmount + $order->delivery_charge - $order->coupon_discount_amount - $order->extra_discount;
            
            $this->line("   🧮 Calculated breakdown:");
            $this->line("      • Subtotal: " . Helpers::set_symbol($calculatedSubtotal));
            $this->line("      • Discount: -" . Helpers::set_symbol($calculatedDiscount));
            $this->line("      • Tax: " . Helpers::set_symbol($calculatedTax));
            $this->line("      • Addon Cost: " . Helpers::set_symbol($calculatedAddonCost));
            $this->line("      • Addon Tax: " . Helpers::set_symbol($calculatedAddonTax));
            $this->line("      • Delivery: " . Helpers::set_symbol($order->delivery_charge));
            $this->line("      • Coupon Discount: -" . Helpers::set_symbol($order->coupon_discount_amount));
            $this->line("      • Extra Discount: -" . Helpers::set_symbol($order->extra_discount));
            $this->line("   🎯 Expected total: " . Helpers::set_symbol($expectedOrderAmount));
            
            // Check consistency
            if (abs($expectedOrderAmount - $storedOrderAmount) < 0.01) {
                $this->info("   ✅ Order amount is consistent!");
            } else {
                $this->error("   ❌ Order amount mismatch! Expected: {$expectedOrderAmount}, Stored: {$storedOrderAmount}");
            }
            
            // 3. Check delivery charge inclusion
            if ($order->delivery_charge > 0) {
                $this->line("   🚚 Delivery charge: " . Helpers::set_symbol($order->delivery_charge) . " (included in order_amount)");
            }
            
            $this->line("");
        }
        
        $this->info("✅ Verification complete!");
        $this->info("💡 Key points:");
        $this->info("   • order_amount should include all charges (items + tax + delivery - discounts)");
        $this->info("   • Order list and order details should show the same order_amount");
        $this->info("   • All prices should come from branch-specific data");
        
        return 0;
    }
}