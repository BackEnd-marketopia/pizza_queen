<?php

// Test script to verify order processing fix
require __DIR__ . '/vendor/autoload.php';

use Illuminate\Http\Request;
use App\Http\Controllers\Api\V1\OrderController;

// Create a sample request to test the order logic
$requestData = [
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
            "is_free" => true, // This should be IGNORED for main product
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

echo "Test data prepared.\n";
echo "Main product should be is_free=false even though request has is_free=true\n";
echo "Only 2 products should be inserted: main product + free product\n";
echo "Check logs for detailed tracking with request_id\n";