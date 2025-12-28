<?php

namespace App\Http\Controllers\Api\V1;

use App\CentralLogics\CustomerLogic;
use App\CentralLogics\Helpers;
use App\CentralLogics\OrderLogic;
use App\Http\Controllers\Controller;
use App\Model\AddOn;
use App\Model\Branch;
use Illuminate\Support\Facades\Log;
use App\Model\BusinessSetting;
use App\Model\Coupon;
use App\Model\CustomerAddress;
use App\Model\DMReview;
use App\Model\Order;
use App\Model\OrderDetail;
use App\Model\Product;
use App\Model\ProductByBranch;
use App\Models\GuestUser;
use App\Models\OfflinePayment;
use App\Models\OrderPartialPayment;
use App\Models\OrderArea;
use App\User;
use Brian2694\Toastr\Facades\Toastr;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use function App\CentralLogics\translate;

class OrderController extends Controller
{
    public function __construct(
        private User            $user,
        private Order           $order,
        private OrderDetail     $order_detail,
        private ProductByBranch $product_by_branch,
        private Product         $product,
        private OfflinePayment  $offlinePayment,
        private BusinessSetting $business_setting,
        private OrderArea $orderArea,
    ) {}

    /**
     * Convert mobile app variations format to POS-compatible format
     * Mobile format: [{"type": "Choose", "value": "Thin رقيقه"}]
     * POS format: [{"name": "Choose", "values": {"label": ["Thin رقيقه"]}}]
     */
    private function convertMobileVariationsToPOSFormat($mobileVariations) {
        $posVariations = [];
        
        if (!is_array($mobileVariations)) {
            return $posVariations;
        }
        
        foreach ($mobileVariations as $variation) {
            if (isset($variation['type']) && isset($variation['value'])) {
                $posVariations[] = [
                    'name' => $variation['type'],
                    'values' => [
                        'label' => [$variation['value']]
                    ]
                ];
            }
        }
        
        Log::info('Converted mobile variations to POS format', [
            'mobile_variations' => $mobileVariations,
            'pos_variations' => $posVariations
        ]);
        
        return $posVariations;
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function trackOrder(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'order_id' => 'required',
            'guest_id' => auth('api')->user() ? 'nullable' : 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
        $userType = (bool)auth('api')->user() ? 0 : 1;

        $order = $this->order->where(['id' => $request['order_id'], 'user_id' => $userId, 'is_guest' => $userType])->first();
        if (!isset($order)) {
            return response()->json([
                'errors' => [
                    ['code' => 'order', 'message' => translate('Order not found!')]
                ]
            ], 404);
        }

        return response()->json(OrderLogic::track_order($request['order_id']), 200);
    }

    /**
     * EMERGENCY: Ultra-strict order placement to prevent data corruption
     */
    public function placeOrder(Request $request): JsonResponse
    {
        // Generate unique request ID and lock
        $request_id = 'emergency_' . uniqid() . '_' . time();
        
        Log::emergency('ULTRA STRICT ORDER START', [
            'request_id' => $request_id,
            'timestamp' => now(),
            'cart_items' => count($request['cart'] ?? []),
            'user_agent' => $request->header('User-Agent', 'unknown'),
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

        //update daily stock
        Helpers::update_daily_product_stock();

        if (auth('api')->user()) {
            $customer = $this->user->find(auth('api')->user()->id);
        }

        if ($request->payment_method == 'wallet_payment') {
            if (Helpers::get_business_settings('wallet_status') != 1) {
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('customer_wallet_status_is_disable')]]], 403);
            }
            if (isset($customer) && $customer->wallet_balance < $request['order_amount']) {
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('you_do_not_have_sufficient_balance_in_wallet')]]], 403);
            }
        }

        if ($request['is_partial'] == 1) {
            if (Helpers::get_business_settings('wallet_status') != 1) {
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('customer_wallet_status_is_disable')]]], 403);
            }
            if (isset($customer) && $customer->wallet_balance > $request['order_amount']) {
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('since your wallet balance is more than order amount, you can not place partial order')]]], 403);
            }
            if (isset($customer) && $customer->wallet_balance < 1) {
                return response()->json(['errors' => [['code' => 'payment_method', 'message' => translate('since your wallet balance is less than 1, you can not place partial order')]]], 403);
            }
        }

        // $preparation_time = Helpers::get_business_settings('default_preparation_time') ?? 0;
        $preparation_time = Branch::where(['id' => $request['branch_id']])->first()->preparation_time ?? 0;

        if ($request['delivery_time'] == 'now') {
            $deliveryDate = Carbon::now('Africa/Cairo')->format('Y-m-d');
            $deliveryTime = Carbon::now('Africa/Cairo')->add($preparation_time, 'minute')->format('H:i:s');
        } else {
            $deliveryDate = $request['delivery_date'];
            $deliveryTime = Carbon::parse($request['delivery_time'])->add($preparation_time, 'minute')->format('H:i:s');
        }

        $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
        $userType = (bool)auth('api')->user() ? 0 : 1;

        if ($request->is_partial == 1) {
            $paymentStatus = ($request->payment_method == 'cash_on_delivery' || $request->payment_method == 'offline_payment') ? 'partial_paid' : 'paid';
        } else {
            $paymentStatus = ($request->payment_method == 'cash_on_delivery' || $request->payment_method == 'offline_payment') ? 'unpaid' : 'paid';
        }

        $orderStatus = ($request->payment_method == 'cash_on_delivery' || $request->payment_method == 'offline_payment') ? 'pending' : 'confirmed';

        if ($request['order_type'] == 'take_away') {
            $deliveryCharge = 0;
        } else {
            $deliveryCharge = Helpers::get_delivery_charge(branchId: $request['branch_id'], distance: $request['distance'], selectedDeliveryArea: $request['selected_delivery_area']);
        }

        try {
            // CRITICAL: Start isolated transaction with row locks
            DB::beginTransaction();
            
            $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
            $userType = (bool)auth('api')->user() ? 0 : 1;
            
            // EMERGENCY: Kill any corrupted orders for this user in last 2 minutes
            $corruptedOrders = DB::select("
                SELECT o.id, COUNT(od.id) as product_count 
                FROM orders o 
                JOIN order_details od ON o.id = od.order_id 
                WHERE o.user_id = ? AND o.is_guest = ? 
                AND o.created_at >= DATE_SUB(NOW(), INTERVAL 2 MINUTE)
                AND o.order_status IN ('pending', 'confirmed')
                GROUP BY o.id 
                HAVING product_count > 4
            ", [$userId, $userType]);
            
            if (!empty($corruptedOrders)) {
                $corruptedIds = array_column($corruptedOrders, 'id');
                Log::emergency('KILLING CORRUPTED ORDERS', [
                    'request_id' => $request_id,
                    'corrupted_orders' => $corruptedIds
                ]);
                
                DB::table('orders')->whereIn('id', $corruptedIds)->update([
                    'order_status' => 'cancelled_emergency',
                    'updated_at' => now()
                ]);
                
                // CRITICAL: Delete corrupted order details
                DB::table('order_details')->whereIn('order_id', $corruptedIds)->delete();
            }
            
            // CRITICAL: Generate GUARANTEED unique order ID using microseconds
            $microtime = microtime(true);
            $unique_suffix = substr(str_replace('.', '', $microtime), -6);
            $order_id = 100000 + (int)$unique_suffix;
            
            // DOUBLE CHECK: Ensure this ID is absolutely clean
            $attempts = 0;
            while ($attempts < 20) {
                $existingOrder = DB::table('orders')->where('id', $order_id)->exists();
                $existingDetails = DB::table('order_details')->where('order_id', $order_id)->count();
                
                if (!$existingOrder && $existingDetails === 0) {
                    break; // ID is clean
                }
                
                // If any data exists, force clean it and try next ID
                if ($existingDetails > 0) {
                    Log::emergency('FORCE CLEANING EXISTING ORDER DATA', [
                        'request_id' => $request_id,
                        'order_id' => $order_id,
                        'existing_details' => $existingDetails
                    ]);
                    DB::table('order_details')->where('order_id', $order_id)->delete();
                }
                
                if ($existingOrder) {
                    DB::table('orders')->where('id', $order_id)->update([
                        'order_status' => 'overwritten_emergency',
                        'updated_at' => now()
                    ]);
                }
                
                $order_id++;
                $attempts++;
            }
            
            if ($attempts >= 20) {
                throw new \Exception('Could not generate clean order ID after 20 attempts');
            }
            
            Log::emergency('ORDER ID SECURED AND GUARANTEED CLEAN', [
                'request_id' => $request_id,
                'order_id' => $order_id,
                'attempts' => $attempts,
                'microtime_suffix' => $unique_suffix
            ]);
            $or = [
                'id' => $order_id,
                'user_id' => $userId,
                'is_guest' => $userType,
                'order_amount' => 0, // Will be calculated after processing cart items
                'coupon_discount_amount' => 0, // Will be calculated by backend, not from request
                'coupon_discount_title' => null, // Will be set by backend if coupon is valid
                'payment_status' => $paymentStatus,
                'order_status' => $orderStatus,
                'coupon_code' => $request['coupon_code'] ?? null,
                'payment_method' => $request->payment_method,
                'transaction_reference' => $request->transaction_reference ?? null,
                'order_note' => $request['order_note'],
                'order_type' => $request['order_type'],
                'branch_id' => $request['branch_id'],
                'delivery_address_id' => $request->delivery_address_id,
                'delivery_date' => $deliveryDate,
                'delivery_time' => $deliveryTime,
                'delivery_address' => json_encode(CustomerAddress::find($request->delivery_address_id) ?? null),
                'delivery_charge' => $deliveryCharge,
                'preparation_time' => 0,
                'is_cutlery_required' => $request['is_cutlery_required'] ?? 0,
                'checked' => 0, // For notification system
                'created_at' => now('Africa/Cairo'),
                'updated_at' => now('Africa/Cairo')
            ];
            $totalTaxAmount = 0;
            $totalAddonPrice = 0;
            $totalAddonTax = 0;
            $productPrice = 0;
            $free_product = null;
            $inserted_products_count = 0;
            
            Log::info('Starting cart processing', [
                'request_id' => $request_id,
                'cart_items' => count($request['cart'])
            ]);
            
            foreach ($request['cart'] as $cart_index => $c) {
                Log::info('Processing cart item', [
                    'request_id' => $request_id,
                    'cart_index' => $cart_index,
                    'product_id' => $c['product_id'],
                    'has_free_product' => isset($c['free_product'])
                ]);
                $product = $this->product->find($c['product_id']);
                
                // CRITICAL: Validate product exists and belongs to correct branch
                if (!$product) {
                    Log::error('Product not found', [
                        'request_id' => $request_id,
                        'product_id' => $c['product_id']
                    ]);
                    throw new \Exception("Product {$c['product_id']} not found");
                }
                
                // CRITICAL: Double-check we're processing the right product
                Log::info('Product validation', [
                    'request_id' => $request_id,
                    'expected_product_id' => $c['product_id'],
                    'found_product_id' => $product->id,
                    'product_name' => $product->name
                ]);
                $branch_product = $this->product_by_branch->where(['product_id' => $c['product_id'], 'branch_id' => $request['branch_id']])->first();
                
                // Handle mobile app variation format - convert mobile format to POS format
                $convertedVariations = [];
                
                // Check if mobile app sent variations in the main product
                if (isset($c['variations']) && is_array($c['variations']) && !empty($c['variations'])) {
                    // Mobile app format: [{"type": "Choose", "value": "Thin رقيقه"}]
                    $convertedVariations = $this->convertMobileVariationsToPOSFormat($c['variations']);
                    
                    Log::info('Main product mobile variations found and converted', [
                        'request_id' => $request_id,
                        'product_id' => $c['product_id'],
                        'mobile_variations' => $c['variations'],
                        'converted_variations' => $convertedVariations
                    ]);
                } else if (isset($c['variation'])) {
                    // Fallback: handle old format or price-based variation detection
                    $parsedVariation = json_decode($c['variation'], true);
                    if (is_array($parsedVariation) && !empty($parsedVariation)) {
                        // Try to convert if it looks like mobile format
                        if (isset($parsedVariation[0]['type']) && isset($parsedVariation[0]['value'])) {
                            $convertedVariations = $this->convertMobileVariationsToPOSFormat($parsedVariation);
                        }
                    }
                    
                    Log::info('Main product variation fallback processing', [
                        'request_id' => $request_id,
                        'product_id' => $c['product_id'],
                        'mobile_variation' => $c['variation'] ?? null,
                        'converted_variations' => $convertedVariations
                    ]);
                } else {
                    Log::info('No variations found in main product', [
                        'request_id' => $request_id,
                        'product_id' => $c['product_id']
                    ]);
                }
                
                $free_product_data = null;
                if (isset($c['free_product']) && ($c['free_product']['product_id'] ?? $c['free_product']['productId'] ?? null) != null) {
                    $free_product = $this->product->find($c['free_product']['product_id'] ?? $c['free_product']['productId']);
                    $free_product->price = $c['free_product']['price'] ?? 0;
                    $free_product['qty'] = $c['free_product']['qty'] ?? 0;
                    $branch_product_free = $this->product_by_branch->where(['product_id' => $c['free_product']['product_id'] ?? $c['free_product']['productId'], 'branch_id' => $request['branch_id']])->first();
                    if ($branch_product_free && ($branch_product_free->stock_type == 'daily' || $branch_product_free->stock_type == 'fixed')) {
                        $available_stock_free = $branch_product_free->stock - $branch_product_free->sold_quantity;
                        if ($available_stock_free < ($c['free_product']['qty'] ?? 0)) {
                            return response()->json(['errors' => [['code' => 'stock', 'message' => translate('stock limit exceeded for free product')]]], 403);
                        }
                    }
                    // Calculate variations and addons for free product like POS
                    $free_product_price = 0; // Start with 0 for free products
                    $free_product_display_price = 0; // This will show in order (variations only)
                    $free_variations = [];
                    $free_add_on_prices = [];
                    $free_add_on_taxes = [];
                    $free_total_addon_tax = 0;

                    // Add variation price to the free product
                    if ($branch_product_free) {
                        $branch_product_free_variations = $branch_product_free->variations;
                        if (count($branch_product_free_variations) && isset($c['free_product']['variations'])) {
                            $convertedFreeVariations = $this->convertMobileVariationsToPOSFormat($c['free_product']['variations']);
                            $free_variation_data = Helpers::get_varient($branch_product_free_variations, $convertedFreeVariations);
                            
                            // Free product displays variation cost but doesn't add to product price for Items Price calculation
                            $free_product_display_price = $free_variation_data['price']; // For display in order
                            $free_variations = $free_variation_data['variations'];
                            
                            // CRITICAL: Add free product variation price to total addon price (like POS)
                            // This ensures variation cost appears in "Addon Cost" section
                            $totalAddonPrice += $free_variation_data['price'] * ($c['free_product']['qty'] ?? 1);
                            
                            Log::info('Free product variation calculated', [
                                'request_id' => $request_id,
                                'free_product_id' => $free_product->id,
                                'variation_price' => $free_variation_data['price'],
                                'display_price' => $free_product_display_price,
                                'variation_qty' => $c['free_product']['qty'] ?? 1,
                                'total_variation_cost' => $free_variation_data['price'] * ($c['free_product']['qty'] ?? 1),
                                'variation_details' => $free_variations,
                                'note' => 'Free product shows variation cost in order display, adds to Addon Cost'
                            ]);
                        }
                        } else {
                            // Handle case where no branch-specific product but general product variations exist
                            $general_product_variations = json_decode($free_product->variations ?? '[]', true) ?: [];
                            if (count($general_product_variations) && isset($c['free_product']['variations'])) {
                                $convertedFreeVariations = $this->convertMobileVariationsToPOSFormat($c['free_product']['variations']);
                                $free_variation_data = Helpers::get_varient($general_product_variations, $convertedFreeVariations);
                                
                                // Free product displays variation cost but doesn't add to product price for Items Price calculation
                                $free_product_display_price = $free_variation_data['price']; // For display in order
                                $free_variations = $free_variation_data['variations'];
                                
                                // CRITICAL: Add free product variation price to total addon price (like POS)
                                $totalAddonPrice += $free_variation_data['price'] * ($c['free_product']['qty'] ?? 1);
                                
                                Log::info('Free product variation calculated (general product)', [
                                    'request_id' => $request_id,
                                    'free_product_id' => $free_product->id,
                                    'variation_price' => $free_variation_data['price'],
                                    'display_price' => $free_product_display_price,
                                    'variation_qty' => $c['free_product']['qty'] ?? 1,
                                    'total_variation_cost' => $free_variation_data['price'] * ($c['free_product']['qty'] ?? 1),
                                    'note' => 'Using general product variations, shows in display, adds to Addon Cost'
                                ]);
                            }
                        }                    // Add addon prices to free product price (like POS does)
                    if (isset($c['free_product']['add_on_ids']) && count($c['free_product']['add_on_ids'])) {
                        foreach ($c['free_product']['add_on_ids'] as $key => $id) {
                            $addon = AddOn::find($id);
                            if ($addon) {
                                $free_add_on_prices[] = $addon['price'];
                                $free_add_on_taxes[] = ($addon['price'] * $addon['tax']) / 100;
                            } else {
                                Log::error('Free product addon not found', [
                                    'request_id' => $request_id,
                                    'addon_id' => $id
                                ]);
                                $free_add_on_prices[] = 0;
                                $free_add_on_taxes[] = 0;
                            }
                        }
                        $free_total_addon_tax = array_reduce(
                            array_map(function ($a, $b) {
                                return $a * $b;
                            }, $c['free_product']['add_on_qtys'], $free_add_on_taxes),
                            function ($carry, $item) {
                                return $carry + $item;
                            },
                            0
                        );
                        
                        // CRITICAL: Calculate free product addon total price correctly
                        $free_addon_total = array_reduce(
                            array_map(function ($a, $b) {
                                return $a * $b;
                            }, $c['free_product']['add_on_qtys'], $free_add_on_prices),
                            function ($carry, $item) {
                                return $carry + $item;
                            },
                            0
                        );
                        
                        // CRITICAL: Add free product addons to total addon price (like POS)
                        // Multiply by quantity to get total cost
                        $totalAddonPrice += $free_addon_total * ($c['free_product']['qty'] ?? 1);
                        $totalAddonTax += $free_total_addon_tax * ($c['free_product']['qty'] ?? 1);
                        
                        // Addons DON'T add to free product display price (they go to Addon Cost)
                        // $free_product_price += $free_addon_total; // REMOVED: addons go to Addon Cost only
                        
                        Log::info('Free product addons calculated', [
                            'request_id' => $request_id,
                            'free_product_id' => $free_product->id,
                            'addon_total' => $free_addon_total,
                            'addon_qty' => $c['free_product']['qty'] ?? 1,
                            'total_addon_cost' => $free_addon_total * ($c['free_product']['qty'] ?? 1),
                            'addon_tax' => $free_total_addon_tax,
                            'total_addon_tax' => $free_total_addon_tax * ($c['free_product']['qty'] ?? 1),
                            'addon_prices' => $free_add_on_prices,
                            'addon_qtys' => $c['free_product']['add_on_qtys'],
                            'note' => 'Addons go to Addon Cost only, not included in free product display price'
                        ]);
                        
                        // Free product does NOT contribute to productPrice (Items Price)
                        // Only addons are counted in Addon Cost
                    }

                    $free_product_data = [
                        'product' => $free_product,
                        'price' => $free_product_display_price, // Shows only variation cost, not addons
                        'qty' => $c['free_product']['qty'] ?? 0,
                        'variations' => $free_variations,
                        'add_on_ids' => $c['free_product']['add_on_ids'] ?? [],
                        'add_on_qtys' => $c['free_product']['add_on_qtys'] ?? [],
                        'add_on_prices' => $free_add_on_prices,
                        'add_on_taxes' => $free_add_on_taxes,
                        'add_on_tax_amount' => $free_total_addon_tax,
                        'tax_amount' => 0, // POS-style: Free products have 0 tax
                        'display_price' => $free_product_display_price, // For order display: shows variation cost only
                        'note' => 'Free product displays variation cost only, addons go to Addon Cost section'
                    ];
                }

                //daily and fixed stock quantity validation for main product
                if ($branch_product && ($branch_product->stock_type == 'daily' || $branch_product->stock_type == 'fixed')) {
                    $available_stock = $branch_product->stock - $branch_product->sold_quantity;
                    if ($available_stock < $c['quantity']) {
                        return response()->json(['errors' => [['code' => 'stock', 'message' => translate('stock limit exceeded')]]], 403);
                    }
                }

                $discount_data = [];

                $discount_data = [];
                $base_price = 0;
                $variation_price = 0;

                if ($branch_product) {
                    $branch_product_variations = $branch_product->variations;
                    $variations = [];
                    $base_price = $branch_product['price'];
                    
                    if (count($branch_product_variations)) {
                        $variation_data = Helpers::get_varient($branch_product_variations, $convertedVariations);
                        $variation_price = $variation_data['price'];
                        // Like POS: variation price is included in product price
                        $price = $base_price + $variation_price;
                        $variations = $variation_data['variations'];
                    } else {
                        $price = $base_price;
                    }
                    $discount_data = [
                        'discount_type' => $branch_product['discount_type'],
                        'discount' => $branch_product['discount'],
                    ];
                } else {
                    $product_variations = json_decode($product->variations, true);
                    $variations = [];
                    $base_price = $product['price'];
                    
                    if (count($product_variations)) {
                        $variation_data = Helpers::get_varient($product_variations, $convertedVariations);
                        $variation_price = $variation_data['price'];
                        // Like POS: variation price is included in product price
                        $price = $base_price + $variation_price;
                        $variations = $variation_data['variations'];
                    } else {
                        $price = $base_price;
                    }
                    $discount_data = [
                        'discount_type' => $product['discount_type'],
                        'discount' => $product['discount'],
                    ];
                }

                // CRITICAL: Main product is NEVER free, even if request says is_free: true
                // Only the free_product (if exists) should be marked as free
                $is_current_product_free = false; // Main product is always charged normally
                
                // For main products: always use full price for both items and tax
                $product_price_for_items = $price; // Full price (base + variation + addon)
                $product_price_for_tax = $price; // Full price for tax calculation
                
                Log::info('Processing MAIN product', [
                    'request_id' => $request_id,
                    'product_id' => $c['product_id'],
                    'base_price' => $base_price,
                    'variation_price' => $variation_price,
                    'full_price' => $price,
                    'final_price_for_items' => $product_price_for_items,
                    'note' => 'Main product - always charged normally, never free'
                ]);

                $discount_on_product = Helpers::discount_calculate($discount_data, $product_price_for_items);

                /*calculation for addon and addon tax start*/
                $add_on_quantities = $c['add_on_qtys'];
                $add_on_prices = [];
                $add_on_taxes = [];
                $total_addon_price = 0;

                foreach ($c['add_on_ids'] as $key => $id) {
                    $addon = AddOn::find($id);
                    if ($addon) {
                        $add_on_prices[] = $addon['price'];
                        $add_on_taxes[] = ($addon['price'] * $addon['tax']) / 100;
                        $total_addon_price += $addon['price'] * $add_on_quantities[$key];
                    } else {
                        Log::error('Main product addon not found', [
                            'request_id' => $request_id,
                            'addon_id' => $id
                        ]);
                        $add_on_prices[] = 0;
                        $add_on_taxes[] = 0;
                    }
                }

                $total_addon_tax = array_reduce(
                    array_map(function ($a, $b) {
                        return $a * $b;
                    }, $add_on_quantities, $add_on_taxes),
                    function ($carry, $item) {
                        return $carry + $item;
                    },
                    0
                );

                /*calculation for addon and addon tax end*/

                // Calculate product subtotal like POS
                $productSubtotal = ($product_price_for_items - $discount_on_product) * $c['quantity'];
                $productPrice += $productSubtotal;
                
                // CRITICAL: Multiply main product addon cost by quantity (like POS)
                $totalAddonPrice += $total_addon_price * $c['quantity'];
                $totalAddonTax += $total_addon_tax * $c['quantity'];
                
                Log::info('Main product totals calculated', [
                    'request_id' => $request_id,
                    'product_id' => $c['product_id'],
                    'product_subtotal' => $productSubtotal,
                    'addon_price_per_item' => $total_addon_price,
                    'quantity' => $c['quantity'],
                    'total_addon_cost' => $total_addon_price * $c['quantity'],
                    'addon_tax_per_item' => $total_addon_tax,
                    'total_addon_tax' => $total_addon_tax * $c['quantity'],
                    'note' => 'POS-style: addon cost and tax multiplied by quantity'
                ]);

                // CRITICAL: Prepare safe data for database columns
                $safe_variant = $c['variant'] ?? null;
                if (is_array($safe_variant)) {
                    $safe_variant = json_encode($safe_variant);
                }
                // Ensure variant column doesn't exceed database limit (usually VARCHAR(255) or TEXT)
                if (strlen($safe_variant) > 500) {
                    $safe_variant = json_encode(['truncated' => 'data_too_long']);
                    Log::warning('Variant data truncated', [
                        'request_id' => $request_id,
                        'product_id' => $c['product_id'],
                        'original_size' => strlen(json_encode($c['variant'] ?? []))
                    ]);
                }
                
                $or_d = [
                    'order_id' => $order_id,
                    'product_id' => $c['product_id'],
                    'product_details' => $product,
                    'free_product'  => $free_product_data ? json_encode($free_product_data) : null,
                    'quantity' => $c['quantity'],
                    'price' => $product_price_for_items,
                    'tax_amount' => $is_current_product_free ? 0 : Helpers::tax_calculate($product, $base_price), // FIXED: tax on base price only
                    'discount_on_product' => $discount_on_product,
                    'discount_type' => 'discount_on_product',
                    'variant' => $safe_variant, // FIXED: Safe variant data
                    'variation' => json_encode($variations),
                    'add_on_ids' => json_encode($c['add_on_ids']),
                    'add_on_qtys' => json_encode($c['add_on_qtys']),
                    'add_on_prices' => json_encode($add_on_prices),
                    'add_on_taxes' => json_encode($add_on_taxes),
                    'add_on_tax_amount' => $total_addon_tax,
                    'is_free' => false, // Main product is NEVER free
                    'free_for_product_id' => null,
                    'created_at' => now('Africa/Cairo'),
                    'updated_at' => now('Africa/Cairo')
                ];

                // Log order detail structure for comparison with POS
                Log::info('API Order Detail Structure', [
                    'request_id' => $request_id,
                    'order_id' => $order_id,
                    'product_id' => $c['product_id'],
                    'is_free' => false, // Always false for main product
                    'variation_structure' => $variations,
                    'add_on_ids' => $c['add_on_ids'],
                    'add_on_qtys' => $c['add_on_qtys'],
                    'add_on_prices' => $add_on_prices,
                    'price_calculation' => [
                        'original_request_price' => $c['price'] ?? 0,
                        'base_price' => $base_price,
                        'variation_price' => $variation_price,
                        'final_calculated_price' => $price,
                        'discount' => $discount_on_product,
                        'addon_total_price' => $total_addon_price,
                        'addon_total_tax' => $total_addon_tax,
                        'note' => 'POS-style: variation price included in product price, addon price calculated separately'
                    ],
                    'free_product_data' => $free_product_data ? [
                        'product_id' => $free_product_data['product']->id ?? null,
                        'qty' => $free_product_data['qty'] ?? 0,
                        'price' => $free_product_data['price'] ?? 0,
                        'addon_ids' => $free_product_data['add_on_ids'] ?? [],
                        'addon_prices' => $free_product_data['add_on_prices'] ?? []
                    ] : null
                ]);
                // $or_d['product_details']->push($free_products);
                $totalTaxAmount += $or_d['tax_amount'] * $c['quantity'];
                
                // CRITICAL: Validate order detail before insertion
                Log::info('Inserting main product', [
                    'request_id' => $request_id,
                    'order_id' => $order_id,
                    'product_id' => $or_d['product_id'],
                    'product_name' => $product->name,
                    'price' => $or_d['price'],
                    'is_free' => $or_d['is_free']
                ]);
                
                $this->order_detail->insert($or_d);
                $inserted_products_count++;

                // Insert order detail for free product if exists
                if ($free_product_data && $free_product_data['qty'] > 0) {
                    $free_or_d = [
                        'order_id' => $order_id,
                        'product_id' => $c['free_product']['product_id'] ?? $c['free_product']['productId'],
                        'product_details' => $free_product,
                        'free_product' => null, // No free product for the free product itself
                        'quantity' => $free_product_data['qty'],
                        'price' => $free_product_data['display_price'], // FIXED: Show variation price like POS (not 0)
                        'tax_amount' => 0, // POS-style: Free products have 0 tax
                        'discount_on_product' => 0, // Assuming no discount for free product
                        'discount_type' => 'discount_on_product',
                        'variant' => json_encode([]), // FIXED: Empty for free products to avoid size issues
                        'variation' => json_encode($free_product_data['variations']),
                        'add_on_ids' => json_encode($free_product_data['add_on_ids']),
                        'add_on_qtys' => json_encode($free_product_data['add_on_qtys']),
                        'add_on_prices' => json_encode($free_product_data['add_on_prices']),
                        'add_on_taxes' => json_encode($free_product_data['add_on_taxes']),
                        'add_on_tax_amount' => $free_product_data['add_on_tax_amount'],
                        'is_free' => true, // Mark as free
                        'free_for_product_id' => $c['product_id'], // Reference to the main product
                        'created_at' => now('Africa/Cairo'),
                        'updated_at' => now('Africa/Cairo')
                    ];
                    // POS-style: Don't add tax for free products to total tax amount
                    // $totalTaxAmount += $free_or_d['tax_amount'] * $free_product_data['qty'];
                    
                    // CRITICAL: Validate free product before insertion
                    Log::info('Inserting free product', [
                        'request_id' => $request_id,
                        'order_id' => $order_id,
                        'product_id' => $free_or_d['product_id'],
                        'product_name' => $free_product->name,
                        'price' => $free_or_d['price'],
                        'variation_price' => $free_product_data['display_price'],
                        'is_free' => $free_or_d['is_free'],
                        'note' => 'Free product shows variation price in order detail (like POS)'
                    ]);
                    
                    $this->order_detail->insert($free_or_d);
                    $inserted_products_count++;

                    // Update stock for free product
                    if ($branch_product_free && ($branch_product_free->stock_type == 'daily' || $branch_product_free->stock_type == 'fixed')) {
                        $branch_product_free->sold_quantity += $free_product_data['qty'];
                        $branch_product_free->save();
                    }
                }

                $this->product->find($c['product_id'])->increment('popularity_count');

                //daily and fixed stock quantity update for main product
                if ($branch_product && ($branch_product->stock_type == 'daily' || $branch_product->stock_type == 'fixed')) {
                    $branch_product->sold_quantity += $c['quantity'];
                    $branch_product->save();
                }
            }

            // Calculate final order amount like POS system (INCLUDING delivery charge)
            $totalPrice = $productPrice + $totalAddonPrice;
            
            // ============================================
            // CRITICAL: SERVER-SIDE COUPON VALIDATION & CALCULATION
            // ============================================
            $couponDiscountAmount = 0;
            $couponDiscountTitle = '';
            
            if (!empty($request['coupon_code'])) {
                $coupon = Coupon::active()->where('code', $request['coupon_code'])->first();
                
                if ($coupon) {
                    $couponValid = true;
                    $couponErrorReason = '';
                    
                    // VALIDATION 1: Check coupon type (first_order vs default)
                    if ($coupon->coupon_type == 'first_order') {
                        // First order coupons only for authenticated users
                        if (!(bool)auth('api')->user()) {
                            $couponValid = false;
                            $couponErrorReason = 'First order coupon requires authentication';
                            Log::warning('First order coupon used by guest', [
                                'request_id' => $request_id,
                                'coupon_code' => $request['coupon_code']
                            ]);
                        } else {
                            // Check if user has previous orders
                            $previousOrdersCount = $this->order->where(['user_id' => auth('api')->user()->id, 'is_guest' => 0])->count();
                            if ($previousOrdersCount > 0) {
                                $couponValid = false;
                                $couponErrorReason = 'First order coupon not valid - user has previous orders';
                                Log::warning('First order coupon used by existing customer', [
                                    'request_id' => $request_id,
                                    'coupon_code' => $request['coupon_code'],
                                    'previous_orders' => $previousOrdersCount
                                ]);
                            }
                        }
                    } else {
                        // VALIDATION 2: Check usage limit for default coupons
                        if ($coupon->limit !== null) {
                            $couponUsageCount = $this->order->where([
                                'user_id' => $userId,
                                'coupon_code' => $request['coupon_code'],
                                'is_guest' => $userType
                            ])->count();
                            
                            if ($couponUsageCount >= $coupon->limit) {
                                $couponValid = false;
                                $couponErrorReason = 'Coupon usage limit exceeded';
                                Log::warning('Coupon limit exceeded', [
                                    'request_id' => $request_id,
                                    'coupon_code' => $request['coupon_code'],
                                    'usage_count' => $couponUsageCount,
                                    'limit' => $coupon->limit
                                ]);
                            }
                        }
                    }
                    
                    if ($couponValid) {
                        // Calculate subtotal (Items Price + Addon Cost) - Same as shown on screen
                        $subtotal = $productPrice + $totalAddonPrice;
                        
                        Log::info('Coupon validation started', [
                            'request_id' => $request_id,
                            'coupon_code' => $request['coupon_code'],
                            'coupon_type' => $coupon->coupon_type,
                            'subtotal' => $subtotal,
                            'min_purchase' => $coupon->min_purchase,
                            'discount' => $coupon->discount,
                            'discount_type' => $coupon->discount_type,
                            'max_discount' => $coupon->max_discount
                        ]);
                        
                        // VALIDATION 3: Check minimum purchase requirement
                        if ($subtotal >= $coupon->min_purchase) {
                            // Calculate discount based on type
                            if ($coupon->discount_type == 'percent') {
                                // Calculate percentage discount
                                $couponDiscountAmount = ($subtotal * $coupon->discount) / 100;
                                
                                // Apply max discount limit
                                if ($couponDiscountAmount > $coupon->max_discount) {
                                    $couponDiscountAmount = $coupon->max_discount;
                                    Log::info('Coupon max discount applied', [
                                        'request_id' => $request_id,
                                        'calculated_discount' => ($subtotal * $coupon->discount) / 100,
                                        'max_discount' => $coupon->max_discount,
                                        'final_discount' => $couponDiscountAmount
                                    ]);
                                }
                            } else {
                                // Amount discount (fixed value)
                                $couponDiscountAmount = $coupon->discount;
                            }
                            
                            $couponDiscountTitle = $coupon->title;
                            
                            Log::info('Coupon applied successfully', [
                                'request_id' => $request_id,
                                'coupon_code' => $request['coupon_code'],
                                'coupon_type' => $coupon->coupon_type,
                                'discount_type' => $coupon->discount_type,
                                'discount_amount' => $couponDiscountAmount,
                                'subtotal' => $subtotal,
                                'calculation' => $coupon->discount_type == 'percent' 
                                    ? "({$subtotal} * {$coupon->discount}%) = {$couponDiscountAmount}"
                                    : "Fixed amount: {$couponDiscountAmount}"
                            ]);
                            
                            // Special log for first order coupons
                            if ($coupon->coupon_type == 'first_order') {
                                Log::info('🎉 FIRST ORDER COUPON SUCCESSFULLY APPLIED', [
                                    'request_id' => $request_id,
                                    'order_id' => $order_id,
                                    'customer_id' => auth('api')->user()->id,
                                    'customer_name' => auth('api')->user()->f_name . ' ' . auth('api')->user()->l_name,
                                    'customer_email' => auth('api')->user()->email,
                                    'customer_phone' => auth('api')->user()->phone,
                                    'coupon_code' => $request['coupon_code'],
                                    'discount_amount' => $couponDiscountAmount,
                                    'order_subtotal' => $subtotal,
                                    'timestamp' => now(),
                                    'note' => 'This is the customer\'s FIRST order with coupon discount'
                                ]);
                            }
                        } else {
                            Log::warning('Coupon minimum purchase not met', [
                                'request_id' => $request_id,
                                'coupon_code' => $request['coupon_code'],
                                'subtotal' => $subtotal,
                                'min_purchase' => $coupon->min_purchase,
                                'difference' => $coupon->min_purchase - $subtotal
                            ]);
                        }
                    } else {
                        Log::warning('Coupon validation failed', [
                            'request_id' => $request_id,
                            'coupon_code' => $request['coupon_code'],
                            'reason' => $couponErrorReason
                        ]);
                    }
                } else {
                    Log::warning('Coupon not found or inactive', [
                        'request_id' => $request_id,
                        'coupon_code' => $request['coupon_code']
                    ]);
                }
            }
            
            // Update order with calculated coupon values
            $or['coupon_discount_amount'] = Helpers::set_price($couponDiscountAmount);
            $or['coupon_discount_title'] = $couponDiscountTitle ?: null;
            
            // Calculate tax using individual product tax calculations (original method)
            // This maintains consistency with how each product tax is calculated
            $finalOrderAmount = $totalPrice + $totalTaxAmount + $totalAddonTax + $deliveryCharge - $couponDiscountAmount;
            
            $or['total_tax_amount'] = $totalTaxAmount;
            $or['order_amount'] = Helpers::set_price($finalOrderAmount);

            // Log the calculation details for debugging
            Log::info('Order calculation details COMPLETE', [
                'request_id' => $request_id,
                'order_id' => $order_id,
                'cart_items_in_request' => count($request['cart']),
                'products_inserted' => $inserted_products_count,
                'requested_order_amount' => $request['order_amount'],
                'calculated_order_amount' => $finalOrderAmount,
                'coupon_validation' => [
                    'client_sent_discount' => $request['coupon_discount_amount'] ?? 0,
                    'server_calculated_discount' => $couponDiscountAmount,
                    'discount_difference' => ($request['coupon_discount_amount'] ?? 0) - $couponDiscountAmount,
                    'note' => 'Server calculation overrides client value for security'
                ],
                'detailed_breakdown' => [
                    'main_product_price' => $productPrice,
                    'total_addon_price' => $totalAddonPrice,
                    'total_tax_amount' => $totalTaxAmount,
                    'total_addon_tax' => $totalAddonTax,
                    'delivery_charge' => $deliveryCharge,
                    'coupon_discount' => $couponDiscountAmount,
                    'subtotal' => $totalPrice,
                    'final_with_delivery' => $finalOrderAmount
                ],
                'final_order_amount_in_db' => $or['order_amount'],
                'calculation_formula' => '(main_product_price + total_addon_price) + (tax + addon_tax) + delivery - discount',
                'expected_total_should_be' => $totalPrice + $deliveryCharge,
                'verification' => [
                    'items_price' => $productPrice,
                    'addon_cost' => $totalAddonPrice,
                    'should_match_screen' => "Items: {$productPrice}, Addons: {$totalAddonPrice}, Subtotal: {$totalPrice}, Delivery: {$deliveryCharge}, Final: {$finalOrderAmount}"
                ]
            ]);

            $o_id = $this->order->insertGetId($or);
            
            // CRITICAL FIX: Don't change order_id after inserting order details!
            // All order details were already inserted with the original $order_id
            // Only use the database ID for subsequent operations, NOT for order details
            $actual_db_id = $o_id;
            
            // CRITICAL: Final verification of inserted data
            $insertedDetails = $this->order_detail->where('order_id', $order_id)->get();
            $actualInsertedCount = $insertedDetails->count();
            
            // DIAGNOSTIC: Check what got inserted
            $mainProducts = $insertedDetails->where('is_free', false);
            $freeProducts = $insertedDetails->where('is_free', true);
            $productBreakdown = [];
            foreach($insertedDetails as $detail) {
                $productBreakdown[] = [
                    'product_id' => $detail->product_id,
                    'is_free' => $detail->is_free ? 'true' : 'false',
                    'price' => $detail->price,
                    'quantity' => $detail->quantity
                ];
            }
            
            Log::info('Final order verification', [
                'request_id' => $request_id,
                'original_order_id' => $order_id,
                'actual_db_id' => $actual_db_id,
                'cart_items_sent' => count($request['cart']),
                'products_we_think_inserted' => $inserted_products_count,
                'products_actually_in_db' => $actualInsertedCount,
                'main_products_count' => $mainProducts->count(),
                'free_products_count' => $freeProducts->count(),
                'detailed_breakdown' => $productBreakdown,
                'all_product_ids' => $insertedDetails->pluck('product_id')->toArray(),
                'all_is_free_flags' => $insertedDetails->pluck('is_free')->toArray()
            ]);
            
            // Check for data corruption patterns
            $duplicateProductIds = $insertedDetails->groupBy('product_id')->filter(function($group) {
                return $group->count() > 2; // More than 2 of same product = suspicious
            })->keys();
            
            if ($duplicateProductIds->isNotEmpty()) {
                Log::error('DUPLICATE PRODUCTS DETECTED', [
                    'request_id' => $request_id,
                    'duplicate_product_ids' => $duplicateProductIds->toArray(),
                    'this_indicates' => 'Loop or session contamination issue'
                ]);
            }
            
            // Only check if we have reasonable number of products (not too many)
            if ($actualInsertedCount > 20) { // Increased limit for testing
                Log::error('Too many products detected - ROLLING BACK', [
                    'request_id' => $request_id,
                    'actual_count' => $actualInsertedCount,
                    'product_ids' => $insertedDetails->pluck('product_id')->toArray(),
                    'warning' => 'Data corruption protection triggered - investigate immediately'
                ]);
                DB::rollBack();
                throw new \Exception('Too many products inserted - data corruption detected');
            }
            
            // CRITICAL: Commit transaction
            DB::commit();

            if ($request->payment_method == 'wallet_payment') {
                $amount = $or['order_amount'] + $or['delivery_charge'];
                CustomerLogic::create_wallet_transaction($userId, $amount, 'order_place', $actual_db_id);
            }

            if ($request->payment_method == 'offline_payment') {
                $offlinePayment = $this->offlinePayment;
                $offlinePayment->order_id = $actual_db_id;
                $offlinePayment->payment_info = json_encode($request['payment_info']);
                $offlinePayment->save();
            }

            if ($request['is_partial'] == 1) {
                $totalOrderAmount = $or['order_amount'] + $or['delivery_charge'];
                $walletAmount = $customer->wallet_balance;
                $dueAmount = $totalOrderAmount - $walletAmount;

                $walletTransaction = CustomerLogic::create_wallet_transaction($userId, $walletAmount, 'order_place', $actual_db_id);

                $partial = new OrderPartialPayment;
                $partial->order_id = $actual_db_id;
                $partial->paid_with = 'wallet_payment';
                $partial->paid_amount = $walletAmount;
                $partial->due_amount = $dueAmount;
                $partial->save();

                if ($request['payment_method'] != 'cash_on_delivery') {
                    $partial = new OrderPartialPayment;
                    $partial->order_id = $actual_db_id;
                    $partial->paid_with = $request['payment_method'];
                    $partial->paid_amount = $dueAmount;
                    $partial->due_amount = 0;
                    $partial->save();
                }
            }

            if ($request['selected_delivery_area']) {
                $orderArea = $this->orderArea;
                $orderArea->order_id = $actual_db_id;
                $orderArea->branch_id = $request['branch_id'];
                $orderArea->area_id = $request['selected_delivery_area'];
                $orderArea->save();
            }

            if ((bool)auth('api')->user()) {
                $fcmToken = auth('api')->user()->cm_firebase_token;
                $local = auth('api')->user()->language_code;
                $customerName = auth('api')->user()->f_name . ' ' . auth('api')->user()->l_name;
            } else {
                $guest = GuestUser::find($request['guest_id']);
                $fcmToken = $guest ? $guest->fcm_token : '';
                $local = 'en';
                $customerName = 'Guest User';
            }

            $message = Helpers::order_status_update_message($orderStatus);

            if ($local != 'en') {
                $statusKey = Helpers::order_status_message_key($orderStatus);
                $translatedMessage = $this->business_setting->with('translations')->where(['key' => $statusKey])->first();
                if (isset($translatedMessage->translations)) {
                    foreach ($translatedMessage->translations as $translation) {
                        if ($local == $translation->locale) {
                            $message = $translation->value;
                        }
                    }
                }
            }
            $restaurantName = Helpers::get_business_settings('restaurant_name');
            $value = Helpers::text_variable_data_format(value: $message, user_name: $customerName, restaurant_name: $restaurantName,  order_id: $actual_db_id);

            try {
                if ($value && isset($fcmToken)) {
                    $data = [
                        'title' => translate('Order'),
                        'description' => $value,
                        'order_id' => (bool)auth('api')->user() ? $actual_db_id : null,
                        'image' => '',
                        'type' => 'order_status',
                    ];
                    Helpers::send_push_notif_to_device($fcmToken, $data);
                }
            } catch (\Exception $e) {
                return response()->json(['message' => $e->getMessage()]);
            }

            try {
                $emailServices = Helpers::get_business_settings('mail_config');
                $orderMailStatus = Helpers::get_business_settings('place_order_mail_status_user');
                if (isset($emailServices['status']) && $emailServices['status'] == 1 && $orderMailStatus == 1 && (bool)auth('api')->user()) {
                    Mail::to(auth('api')->user()->email)->send(new \App\Mail\OrderPlaced($actual_db_id));
                }
            } catch (\Exception $e) {
                return response()->json(['message' => $e->getMessage()]);
            }

            if ($or['order_status'] == 'confirmed') {
                $data = [
                    'title' => translate('You have a new order - (Order Confirmed).'),
                    'description' => $actual_db_id,
                    'order_id' => $actual_db_id,
                    'image' => '',
                    'order_status' => $or['order_status'],
                ];

                try {
                    Helpers::send_push_notif_to_topic(data: $data, topic: "kitchen-{$or['branch_id']}", type: 'general', isNotificationPayloadRemove: true);
                } catch (\Exception $e) {
                    Toastr::warning(translate('Push notification failed!'));
                }
            }

            try {
                $data = [
                    'title' => translate('New Order Notification'),
                    'description' => translate('You have new order, Check Please'),
                    'order_id' => $actual_db_id,
                    'image' => '',
                    'type' => 'new_order_admin',
                ];

                Helpers::send_push_notif_to_topic(data: $data, topic: 'admin_message', type: 'order_request', web_push_link: route('admin.orders.list', ['status' => 'all']));
                Helpers::send_push_notif_to_topic(data: $data, topic: 'branch-order-' . $or['branch_id'] . '-message', type: 'order_request', web_push_link: route('branch.orders.list', ['status' => 'all']));
            } catch (\Exception $e) {
                return response()->json(['message' => $e->getMessage()]);
            }
            
            // FINAL SUCCESS LOG
            Log::info('ORDER PLACED SUCCESSFULLY', [
                'request_id' => $request_id,
                'final_order_id' => $actual_db_id,
                'total_products_inserted' => $inserted_products_count,
                'final_amount' => $or['order_amount']
            ]);
            
            return response()->json([
                'message' => translate('order_success'),
                'order_id' => $actual_db_id
            ], 200);
        } catch (\Exception $e) {
            // CRITICAL: Rollback transaction on any error
            DB::rollBack();
            
            Log::error('Place order error - Transaction rolled back', [
                'request_id' => $request_id ?? 'unknown',
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'request' => $request->all()
            ]);
            return response()->json(['message' => $e->getMessage()]);
        }
    }


    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function getOrderList(Request $request): JsonResponse
    {
        $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
        $userType = (bool)auth('api')->user() ? 0 : 1;
        $orderFilter = $request->order_filter;

        $orders = $this->order->with(['customer', 'delivery_man.rating', 'details'])
            ->withCount('details')
            ->withCount(['details as total_quantity' => function ($query) {
                $query->select(DB::raw('sum(quantity)'));
            }])
            ->where(['user_id' => $userId, 'is_guest' => $userType])
            ->when($orderFilter == 'past_order', function ($query) use ($orderFilter) {
                $query->whereIn('order_status', ['delivered', 'canceled', 'failed', 'returned']);
            })
            ->when($orderFilter == 'running_order', function ($query) use ($orderFilter) {
                $query->whereNotIn('order_status', ['delivered', 'canceled', 'failed', 'returned']);
            })
            ->orderBy('id', 'DESC')
            ->paginate($request['limit'], ['*'], 'page', $request['offset']);


        $orders->getCollection()->transform(function ($data) {
            $data->deliveryman_review_count = DMReview::where(['delivery_man_id' => $data->delivery_man_id, 'order_id' => $data->id])->count();

            $order_id = $data->id;
            $order_details = $this->order_detail->where('order_id', $order_id)->first();
            $product_id = $order_details?->product_id;

            $data->is_product_available = $product_id ? $this->product->find($product_id) ? 1 : 0 : 0;
            $data->details_count = (int)$data->details_count;

            $productImages = $this->order_detail->where('order_id', $order_id)->pluck('product_id')
                ->filter()
                ->map(function ($product_id) {
                    $product = $this->product->find($product_id);
                    return $product ? $product->image : null;
                })->filter();

            $data->product_images = $productImages->toArray();

            // CRITICAL FIX: Recalculate order amounts from order_details to ensure consistency
            // This fixes the issue where order list shows different amounts than actual order
            if ($data->details && $data->details->count() > 0) {
                $itemsPrice = 0;
                $totalAddonCost = 0;
                $totalTax = 0;
                $totalAddonTax = 0;
                $itemDiscount = 0;
                
                foreach ($data->details as $detail) {
                    // Calculate items price (price * quantity) - for ALL products
                    // Note: Free products show their variation price (not 0)
                    $itemsPrice += $detail->price * $detail->quantity;
                    
                    // Calculate addon cost - for ALL products (including free ones)
                    // Note: add_on_prices already contains the price per addon item
                    // We need to multiply by add_on_qtys and product quantity
                    $add_on_prices = is_string($detail->add_on_prices) ? json_decode($detail->add_on_prices, true) : $detail->add_on_prices;
                    $add_on_qtys = is_string($detail->add_on_qtys) ? json_decode($detail->add_on_qtys, true) : $detail->add_on_qtys;
                    
                    if (is_array($add_on_prices) && is_array($add_on_qtys)) {
                        foreach ($add_on_prices as $index => $addon_price) {
                            $addon_qty = $add_on_qtys[$index] ?? 1;
                            // addon price × addon quantity × product quantity
                            $totalAddonCost += $addon_price * $addon_qty * $detail->quantity;
                        }
                    }
                    
                    // Calculate tax - for ALL products
                    $totalTax += $detail->tax_amount * $detail->quantity;
                    $totalAddonTax += $detail->add_on_tax_amount * $detail->quantity;
                    
                    // Calculate item discount - for ALL products
                    $itemDiscount += $detail->discount_on_product * $detail->quantity;
                }
                
                // Calculate subtotal (before delivery, coupons, extra discount)
                $subtotal = $itemsPrice + $totalAddonCost - $itemDiscount;
                
                // CRITICAL FIX: Frontend adds delivery separately
                // So order_amount should NOT include delivery_charge
                // order_amount = subtotal - coupon_discount - extra_discount (NO delivery)
                $orderAmountWithoutDelivery = $subtotal - ($data->coupon_discount_amount ?? 0) - ($data->extra_discount ?? 0);
                
                // Override order amounts with recalculated values
                $data->items_price = Helpers::set_price($itemsPrice);
                $data->addon_cost = Helpers::set_price($totalAddonCost);
                $data->total_tax_amount = Helpers::set_price($totalTax + $totalAddonTax);
                $data->item_discount = Helpers::set_price($itemDiscount);
                $data->subtotal = Helpers::set_price($subtotal);
                $data->order_amount = Helpers::set_price($orderAmountWithoutDelivery);
                
                // Note: delivery_charge remains in response but NOT included in order_amount
            }

            return $data;
        });

        $ordersArray = [
            'total_size' => $orders->total(),
            'limit' => $request['limit'],
            'offset' => $request['offset'],
            'orders' => $orders->items(),
        ];

        return response()->json($ordersArray, 200);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function getOrderDetails(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'order_id' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
        $userType = (bool)auth('api')->user() ? 0 : 1;

        $details = $this->order_detail->with([
            'order',
            'order.delivery_man' => function ($query) {
                $query->select('id', 'f_name', 'l_name', 'phone', 'email', 'image', 'branch_id', 'is_active');
            },
            'order.delivery_man.rating',
            'order.delivery_address',
            'order.order_partial_payments',
            'order.offline_payment',
            'order.deliveryman_review'
        ])
            ->withCount(['reviews'])
            ->where(['order_id' => $request['order_id']])
            ->whereHas('order', function ($q) use ($userId, $userType) {
                $q->where(['user_id' => $userId, 'is_guest' => $userType]);
            })
            ->get();

        if ($details->count() < 1) {
            return response()->json([
                'errors' => [
                    ['code' => 'order', 'message' => translate('Order not found!')]
                ]
            ], 404);
        }

        $details = Helpers::order_details_formatter($details);

        // CRITICAL FIX: Recalculate order totals from details to ensure consistency
        // This fixes the issue where order details show different amounts than placed order
        if ($details->count() > 0 && isset($details[0]->order)) {
            $order = $details[0]->order;
            
            $itemsPrice = 0;
            $totalAddonCost = 0;
            $totalTax = 0;
            $totalAddonTax = 0;
            $itemDiscount = 0;
            
            foreach ($details as $detail) {
                // Calculate items price (price * quantity) - for ALL products
                // Note: Free products show their variation price (not 0)
                $itemsPrice += $detail->price * $detail->quantity;
                
                // Calculate addon cost - for ALL products (including free ones)
                // Note: add_on_prices already contains the price per addon item
                // We need to multiply by add_on_qtys and product quantity
                $add_on_prices = is_string($detail->add_on_prices) ? json_decode($detail->add_on_prices, true) : $detail->add_on_prices;
                $add_on_qtys = is_string($detail->add_on_qtys) ? json_decode($detail->add_on_qtys, true) : $detail->add_on_qtys;
                
                if (is_array($add_on_prices) && is_array($add_on_qtys)) {
                    foreach ($add_on_prices as $index => $addon_price) {
                        $addon_qty = $add_on_qtys[$index] ?? 1;
                        // addon price × addon quantity × product quantity
                        $totalAddonCost += $addon_price * $addon_qty * $detail->quantity;
                    }
                }
                
                // Calculate tax - for ALL products
                $totalTax += $detail->tax_amount * $detail->quantity;
                $totalAddonTax += $detail->add_on_tax_amount * $detail->quantity;
                
                // Calculate item discount - for ALL products
                $itemDiscount += $detail->discount_on_product * $detail->quantity;
            }
            
            // Calculate subtotal (before delivery, coupons, extra discount)
            $subtotal = $itemsPrice + $totalAddonCost - $itemDiscount;
            
            // CRITICAL FIX: Frontend adds delivery separately
            // So order_amount should NOT include delivery_charge
            // order_amount = subtotal - coupon_discount - extra_discount (NO delivery)
            $orderAmountWithoutDelivery = $subtotal - ($order->coupon_discount_amount ?? 0) - ($order->extra_discount ?? 0);
            
            // Add recalculated amounts to order object
            $order->items_price = Helpers::set_price($itemsPrice);
            $order->addon_cost = Helpers::set_price($totalAddonCost);
            $order->total_tax_amount = Helpers::set_price($totalTax + $totalAddonTax);
            $order->item_discount = Helpers::set_price($itemDiscount);
            $order->subtotal = Helpers::set_price($subtotal);
            $order->order_amount = Helpers::set_price($orderAmountWithoutDelivery);
            
            // Note: delivery_charge remains in response but NOT included in order_amount
        }

        return response()->json($details, 200);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function cancelOrder(Request $request): JsonResponse
    {
        $order = $this->order::find($request['order_id']);

        if (!isset($order)) {
            return response()->json(['errors' => [['code' => 'order', 'message' => 'Order not found!']]], 404);
        }

        if ($order->order_status != 'pending') {
            return response()->json(['errors' => [['code' => 'order', 'message' => 'Order can only cancel when order status is pending!']]], 403);
        }

        $userId = (bool)auth('api')->user() ? auth('api')->user()->id : $request['guest_id'];
        $userType = (bool)auth('api')->user() ? 0 : 1;

        if ($this->order->where(['user_id' => $userId, 'is_guest' => $userType, 'id' => $request['order_id']])->first()) {
            $this->order->where(['user_id' => $userId, 'is_guest' => $userType, 'id' => $request['order_id']])->update([
                'order_status' => 'canceled'
            ]);
            return response()->json(['message' => translate('order_canceled')], 200);
        }
        return response()->json([
            'errors' => [
                ['code' => 'order', 'message' => translate('no_data_found')]
            ]
        ], 401);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function updatePaymentMethod(Request $request): JsonResponse
    {
        if ($this->order->where(['user_id' => $request->user()->id, 'id' => $request['order_id']])->first()) {
            $this->order->where(['user_id' => $request->user()->id, 'id' => $request['order_id']])->update([
                'payment_method' => $request['payment_method']
            ]);
            return response()->json(['message' => translate('payment_method_updated')], 200);
        }
        return response()->json([
            'errors' => [
                ['code' => 'order', 'message' => translate('no_data_found')]
            ]
        ], 401);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function guestTrackOrder(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'order_id' => 'required',
            'phone' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $orderId = $request->input('order_id');
        $phone = $request->input('phone');

        $order = $this->order->with(['customer', 'delivery_address'])
            ->where('id', $orderId)
            ->where(function ($query) use ($phone) {
                $query->where(function ($subQuery) use ($phone) {
                    $subQuery->where('is_guest', 0)
                        ->whereHas('customer', function ($customerSubQuery) use ($phone) {
                            $customerSubQuery->where('phone', $phone);
                        });
                })
                    ->orWhere(function ($subQuery) use ($phone) {
                        $subQuery->where('is_guest', 1)
                            ->whereHas('delivery_address', function ($addressSubQuery) use ($phone) {
                                $addressSubQuery->where('contact_person_number', $phone);
                            });
                    });
            })
            ->first();


        if (!isset($order)) {
            return response()->json(['errors' => [['code' => 'order', 'message' => translate('Order not found!')]]], 404);
        }

        return response()->json(OrderLogic::track_order($request['order_id']), 200);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function getGuestOrderDetails(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'order_id' => 'required',
            'phone' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $phone = $request->input('phone');

        $details = $this->order_detail->with(['order', 'order.customer', 'order.delivery_address', 'order.order_partial_payments'])
            ->withCount(['reviews'])
            ->where(['order_id' => $request['order_id']])
            ->where(function ($query) use ($phone) {
                $query->where(function ($subQuery) use ($phone) {
                    $subQuery->whereHas('order', function ($orderSubQuery) use ($phone) {
                        $orderSubQuery->where('is_guest', 0)
                            ->whereHas('customer', function ($customerSubQuery) use ($phone) {
                                $customerSubQuery->where('phone', $phone);
                            });
                    });
                })
                    ->orWhere(function ($subQuery) use ($phone) {
                        $subQuery->whereHas('order', function ($orderSubQuery) use ($phone) {
                            $orderSubQuery->where('is_guest', 1)
                                ->whereHas('delivery_address', function ($addressSubQuery) use ($phone) {
                                    $addressSubQuery->where('contact_person_number', $phone);
                                });
                        });
                    });
            })
            ->get();

        if ($details->count() < 1) {
            return response()->json([
                'errors' => [
                    ['code' => 'order', 'message' => translate('Order not found!')]
                ]
            ], 404);
        }

        $details = Helpers::order_details_formatter($details);
        return response()->json($details, 200);
    }
}
