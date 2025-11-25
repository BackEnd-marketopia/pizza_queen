<?php
/**
 * EMERGENCY FIX: Replace the entire placeOrder method with this ultra-strict version
 * Copy this method into OrderController.php to replace the existing placeOrder method
 */

    /**
     * EMERGENCY: Ultra-strict order placement to prevent data corruption
     */
    public function placeOrder(Request $request): JsonResponse
    {
        // Generate unique request ID and emergency lock
        $emergency_id = 'EMERGENCY_' . uniqid() . '_' . time();
        
        Log::emergency('🚨 EMERGENCY ORDER PROCESSING', [
            'emergency_id' => $emergency_id,
            'timestamp' => now(),
            'cart_size' => count($request['cart'] ?? []),
            'user_agent' => substr($request->header('User-Agent', 'unknown'), 0, 100),
            'ip' => $request->ip()
        ]);

        $validator = Validator::make($request->all(), [
            'order_amount' => 'required',
            'payment_method' => 'required',
            'order_type' => 'required',
            'delivery_address_id' => 'required',
            'branch_id' => 'required',
            'delivery_time' => 'required',
            'delivery_date' => 'required',
            'distance' => 'required',
            'guest_id' => auth('api')->user() ? 'nullable' : 'required',
            'is_partial' => 'required|in:0,1',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        if (count($request['cart']) < 1) {
            return response()->json(['errors' => [['code' => 'empty-cart', 'message' => translate('cart is empty')]]], 403);
        }

        // Prevent too many items
        if (count($request['cart']) > 5) {
            Log::emergency('TOO MANY CART ITEMS', ['emergency_id' => $emergency_id, 'count' => count($request['cart'])]);
            return response()->json(['errors' => [['code' => 'cart-limit', 'message' => 'Cart limit exceeded']]], 403);
        }

        try {
            // START EMERGENCY TRANSACTION
            DB::beginTransaction();
            
            $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
            $userType = (bool)auth('api')->user() ? 0 : 1;
            
            // EMERGENCY: Clean corrupted orders from last 5 minutes
            $corrupted = DB::table('orders as o')
                ->join('order_details as od', 'o.id', '=', 'od.order_id')
                ->where('o.user_id', $userId)
                ->where('o.is_guest', $userType)
                ->where('o.created_at', '>=', DB::raw('DATE_SUB(NOW(), INTERVAL 5 MINUTE)'))
                ->whereIn('o.order_status', ['pending', 'confirmed'])
                ->groupBy('o.id')
                ->havingRaw('COUNT(od.id) > 5')
                ->pluck('o.id');
                
            if ($corrupted->count() > 0) {
                Log::emergency('🧹 CLEANING CORRUPTED ORDERS', [
                    'emergency_id' => $emergency_id,
                    'corrupted_ids' => $corrupted->toArray()
                ]);
                
                DB::table('orders')->whereIn('id', $corrupted)->update([
                    'order_status' => 'cancelled_corrupted',
                    'updated_at' => now()
                ]);
            }
            
            // Generate secure order ID
            $orderId = 100000 + DB::table('orders')->count() + 1;
            while (DB::table('orders')->where('id', $orderId)->exists()) {
                $orderId++;
            }
            
            Log::emergency('🆔 ORDER ID GENERATED', [
                'emergency_id' => $emergency_id,
                'order_id' => $orderId
            ]);

            // Build order record
            $deliveryCharge = ($request['order_type'] == 'take_away') ? 0 : 30; // Simple delivery charge
            
            $orderData = [
                'id' => $orderId,
                'user_id' => $userId,
                'is_guest' => $userType,
                'order_amount' => Helpers::set_price($request['order_amount']),
                'coupon_discount_amount' => 0,
                'coupon_discount_title' => null,
                'payment_status' => ($request->payment_method == 'cash_on_delivery') ? 'unpaid' : 'paid',
                'order_status' => ($request->payment_method == 'cash_on_delivery') ? 'pending' : 'confirmed',
                'coupon_code' => $request['coupon_code'] ?? null,
                'payment_method' => $request->payment_method,
                'order_note' => $request['order_note'] ?? null,
                'order_type' => $request['order_type'],
                'branch_id' => $request['branch_id'],
                'delivery_address_id' => $request->delivery_address_id,
                'delivery_date' => $request['delivery_date'],
                'delivery_time' => $request['delivery_time'],
                'delivery_address' => json_encode(CustomerAddress::find($request->delivery_address_id)),
                'delivery_charge' => $deliveryCharge,
                'preparation_time' => 0,
                'is_cutlery_required' => $request['is_cutlery_required'] ?? 0,
                'checked' => 0,
                'created_at' => now('Africa/Cairo'),
                'updated_at' => now('Africa/Cairo')
            ];

            // PROCESS PRODUCTS - ULTRA STRICT
            $productRecords = [];
            $expectedCount = 0;
            
            foreach ($request['cart'] as $index => $item) {
                Log::emergency("📦 PROCESSING ITEM {$index}", [
                    'emergency_id' => $emergency_id,
                    'product_id' => $item['product_id']
                ]);
                
                $product = $this->product->find($item['product_id']);
                if (!$product) {
                    throw new \Exception("Product {$item['product_id']} not found");
                }
                
                // MAIN PRODUCT - NEVER FREE
                $productRecords[] = [
                    'order_id' => $orderId,
                    'product_id' => $item['product_id'],
                    'product_details' => json_encode($product),
                    'quantity' => $item['quantity'] ?? 1,
                    'price' => $item['price'] ?? 1,
                    'tax_amount' => 0,
                    'discount_on_product' => 0,
                    'discount_type' => 'discount_on_product',
                    'variant' => json_encode($item['variant'] ?? ''),
                    'variation' => json_encode($item['variations'] ?? []),
                    'add_on_ids' => json_encode($item['add_on_ids'] ?? []),
                    'add_on_qtys' => json_encode($item['add_on_qtys'] ?? []),
                    'add_on_prices' => json_encode([]),
                    'add_on_taxes' => json_encode([]),
                    'add_on_tax_amount' => 0,
                    'is_free' => 0, // EMERGENCY: NEVER FREE
                    'free_for_product_id' => null,
                    'created_at' => now('Africa/Cairo'),
                    'updated_at' => now('Africa/Cairo')
                ];
                $expectedCount++;
                
                // FREE PRODUCT IF EXISTS
                if (!empty($item['free_product']['product_id'])) {
                    $freeProduct = $this->product->find($item['free_product']['product_id']);
                    if ($freeProduct) {
                        $productRecords[] = [
                            'order_id' => $orderId,
                            'product_id' => $item['free_product']['product_id'],
                            'product_details' => json_encode($freeProduct),
                            'quantity' => $item['free_product']['qty'] ?? 1,
                            'price' => 0,
                            'tax_amount' => 0,
                            'discount_on_product' => 0,
                            'discount_type' => 'discount_on_product',
                            'variant' => json_encode($item['free_product']['variations'] ?? []),
                            'variation' => json_encode($item['free_product']['variations'] ?? []),
                            'add_on_ids' => json_encode($item['free_product']['add_on_ids'] ?? []),
                            'add_on_qtys' => json_encode($item['free_product']['add_on_qtys'] ?? []),
                            'add_on_prices' => json_encode([]),
                            'add_on_taxes' => json_encode([]),
                            'add_on_tax_amount' => 0,
                            'is_free' => 1,
                            'free_for_product_id' => $item['product_id'],
                            'created_at' => now('Africa/Cairo'),
                            'updated_at' => now('Africa/Cairo')
                        ];
                        $expectedCount++;
                    }
                }
            }
            
            // FINAL VALIDATION
            if ($expectedCount === 0 || $expectedCount > 10) {
                throw new \Exception("Invalid product count: {$expectedCount}");
            }
            
            Log::emergency('✅ READY TO INSERT', [
                'emergency_id' => $emergency_id,
                'expected_products' => $expectedCount,
                'cart_items' => count($request['cart'])
            ]);
            
            // INSERT IN SINGLE TRANSACTION
            $dbOrderId = DB::table('orders')->insertGetId($orderData);
            DB::table('order_details')->insert($productRecords);
            
            // VERIFICATION
            $actualCount = DB::table('order_details')->where('order_id', $orderId)->count();
            if ($actualCount !== $expectedCount) {
                throw new \Exception("Verification failed: expected {$expectedCount}, got {$actualCount}");
            }
            
            // COMMIT
            DB::commit();
            
            Log::emergency('🎉 ORDER SUCCESS', [
                'emergency_id' => $emergency_id,
                'order_id' => $dbOrderId,
                'products_inserted' => $actualCount
            ]);

            return response()->json([
                'message' => translate('order_success'),
                'order_id' => $dbOrderId
            ], 200);

        } catch (\Exception $e) {
            DB::rollBack();
            
            Log::emergency('💥 ORDER FAILED', [
                'emergency_id' => $emergency_id,
                'error' => $e->getMessage(),
                'line' => $e->getLine()
            ]);
            
            return response()->json([
                'message' => 'Emergency protection: ' . $e->getMessage()
            ], 500);
        }
    }