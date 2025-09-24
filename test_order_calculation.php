<?php
/**
 * Test Order Calculation
 * محاكاة البيانات المرسلة من التطبيق
 */

$test_request = [
    "user_id" => 50,
    "coupon_code" => null,
    "coupon_discount_amount" => "0.00",
    "payment_method" => "cash_on_delivery",
    "order_amount" => "293.25", // المبلغ الخطأ المرسل من التطبيق
    "order_note" => null,
    "order_type" => "delivery",
    "branch_id" => 1,
    "delivery_address_id" => 22,
    "delivery_time" => "2024-12-20 20:40:00",
    "cart" => [
        [
            "product_id" => 3,
            "price" => "293.25", // خطأ - المفروض 0 للمنتج المجاني
            "variation" => [
                [
                    "type" => "size",
                    "price" => "30.00"
                ]
            ],
            "add_on_ids" => ["1", "2"],
            "add_on_qtys" => ["1", "1"],
            "quantity" => 1,
            "is_free" => true // منتج مجاني!
        ]
    ]
];

echo "=== تحليل البيانات المرسلة ===\n";
echo "Order Amount من التطبيق: " . $test_request['order_amount'] . " EGP\n";
echo "Product Price من التطبيق: " . $test_request['cart'][0]['price'] . " EGP\n";
echo "Is Free Product: " . ($test_request['cart'][0]['is_free'] ? 'Yes' : 'No') . "\n";
echo "Variation Price: " . $test_request['cart'][0]['variation'][0]['price'] . " EGP\n";

echo "\n=== الحساب الصحيح ===\n";
$correct_base_price = 0; // منتج مجاني
$variation_price = 30.00;
$addon_prices = [15.00, 20.00]; // أسعار الإضافات
$addon_total = array_sum($addon_prices);

$correct_product_price = $correct_base_price + $variation_price;
$correct_subtotal = $correct_product_price + $addon_total;

echo "Base Price (Free): " . $correct_base_price . " EGP\n";
echo "Variation Price: " . $variation_price . " EGP\n";
echo "Addon Total: " . $addon_total . " EGP\n";
echo "Product Price: " . $correct_product_price . " EGP\n";
echo "Subtotal: " . $correct_subtotal . " EGP\n";

echo "\n=== المشكلة ===\n";
echo "التطبيق يرسل price = 293.25 للمنتج المجاني\n";
echo "المفروض يرسل price = 0 أو يعتمد على حسابات السيرفر\n";
echo "السيرفر محتاج يتجاهل الـ price المرسل ويحسب الصحيح\n";

?>