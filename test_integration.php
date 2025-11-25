<?php

echo "=== LOCAL INTEGRATION TEST ===\n\n";

// Test data that caused the problem
$testOrder = [
    "cart" => [
        [
            "product_id" => 87,
            "price" => 1,
            "variant" => "",
            "variations" => [
                [
                    "type" => "نوع العجين",
                    "value" => "Thin رقيقه"
                ]
            ],
            "discount_amount" => 0.0,
            "quantity" => 1,
            "tax_amount" => 0.0,
            "add_on_ids" => [14],
            "add_on_qtys" => [1],
            "is_free" => true, // This should be ignored now
            "free_product" => [
                "product_id" => 81,
                "name" => "Small Margherita Pizza Offer",
                "price" => 179.75,
                "qty" => 1,
                "variations" => [
                    [
                        "type" => "نوع العجين",
                        "value" => "Pan سميكه"
                    ]
                ],
                "add_on_ids" => [17],
                "add_on_qtys" => [1]
            ]
        ]
    ],
    "coupon_discount_amount" => 0.0,
    "coupon_discount_title" => "",
    "order_amount" => 160.25,
    "order_type" => "delivery",
    "delivery_address_id" => 52,
    "payment_method" => "cash_on_delivery",
    "order_note" => "",
    "coupon_code" => "",
    "delivery_time" => "now",
    "delivery_date" => "2025-09-24",
    "branch_id" => 10,
    "distance" => -1.0,
    "selected_delivery_area" => null,
    "is_partial" => 0,
    "is_cutlery_required" => 0,
    "guest_id" => "1"
];

echo "🧪 TEST SCENARIO:\n";
echo "Cart items: " . count($testOrder['cart']) . "\n";
echo "Main product: ID " . $testOrder['cart'][0]['product_id'] . "\n";
echo "Free product: ID " . $testOrder['cart'][0]['free_product']['product_id'] . "\n";
echo "Main product has is_free=true (should be ignored)\n\n";

echo "🎯 EXPECTED OUTCOME:\n";
echo "- Total products inserted: 2\n";
echo "- Main product: is_free = false, price > 0\n";
echo "- Free product: is_free = true, price = 0\n";
echo "- No unexpected products (like Spaghetti Seafood)\n";
echo "- Transaction commits successfully\n\n";

echo "🔍 TO TEST:\n";
echo "1. Send POST to: http://localhost:8001/api/v1/customer/order/place\n";
echo "2. Check logs for unique request_id\n";
echo "3. Verify 'ORDER PLACED SUCCESSFULLY' message\n";
echo "4. Check dashboard shows exactly 2 products\n";
echo "5. Verify no foreign products appear\n\n";

echo "📊 MONITORING POINTS:\n";
echo "- 'NEW PLACE ORDER REQUEST STARTED' log\n";
echo "- 'Product validation' logs\n";
echo "- 'Inserting main product' and 'Inserting free product' logs\n";
echo "- 'Final order verification' with product counts\n";
echo "- 'ORDER PLACED SUCCESSFULLY' confirmation\n\n";

echo "Status: Ready for testing 🟢\n";