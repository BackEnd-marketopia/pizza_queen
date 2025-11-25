<?php
/**
 * اختبار Order API endpoint إذا كان السيرفر يعمل
 */

echo "=== اختبار Order API Endpoint ===\n";
echo "التاريخ: " . date('Y-m-d H:i:s') . "\n\n";

// تحديد URL الـ API
$api_url = "http://localhost/pizza_queen/api/v1/customer/order/place";

// بيانات الطلب (نفس بيانات Postman)
$order_data = [
    'cart' => [
        [
            'product_id' => 87,
            'price' => 1,
            'variant' => '',
            'variations' => [
                [
                    'type' => 'نوع العجين',
                    'value' => 'Thin رقيقه'
                ]
            ],
            'discount_amount' => 0.0,
            'quantity' => 1,
            'tax_amount' => 0.0,
            'add_on_ids' => [14],
            'add_on_qtys' => [1],
            'is_free' => true,
            'free_product' => [
                'product_id' => 81,
                'name' => 'Small Margherita Pizza Offer',
                'price' => 0.0,
                'qty' => 1,
                'variations' => [
                    [
                        'type' => 'نوع العجين',
                        'value' => 'Pan سميكه'
                    ]
                ],
                'add_on_ids' => [17],
                'add_on_qtys' => [1]
            ]
        ]
    ],
    'coupon_discount_amount' => 0.0,
    'coupon_discount_title' => '',
    'order_amount' => 293.25,
    'order_type' => 'delivery',
    'delivery_address_id' => 52,
    'payment_method' => 'cash_on_delivery',
    'order_note' => '',
    'coupon_code' => '',
    'delivery_time' => 'now',
    'delivery_date' => '2025-11-25',
    'branch_id' => 10,
    'distance' => -1.0,
    'selected_delivery_area' => null,
    'is_partial' => 0,
    'is_cutlery_required' => 0,
    'guest_id' => 1
];

echo "URL: {$api_url}\n";
echo "Method: POST\n";
echo "Content-Type: application/json\n\n";

// تحقق من إمكانية الوصول للسيرفر
echo "=== تحقق من السيرفر ===\n";

$base_url = "http://localhost/pizza_queen/";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $base_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_NOBODY, true);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($error) {
    echo "❌ خطأ في الاتصال: {$error}\n";
    echo "📝 تأكد من:\n";
    echo "   - AMPPS يعمل\n";
    echo "   - Apache يعمل\n";
    echo "   - المشروع في المسار الصحيح\n";
    echo "   - لا توجد مشاكل في الـ URL\n\n";
} else {
    echo "✅ السيرفر يعمل - HTTP Status: {$http_code}\n\n";
    
    if ($http_code == 200 || $http_code == 302) {
        echo "=== محاولة استدعاء API ===\n";
        
        // استدعاء الـ API
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($order_data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Accept: application/json'
        ]);
        
        $api_response = curl_exec($ch);
        $api_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $api_error = curl_error($ch);
        curl_close($ch);
        
        if ($api_error) {
            echo "❌ خطأ في API: {$api_error}\n";
        } else {
            echo "📡 API Response Status: {$api_http_code}\n";
            echo "📄 Response Body:\n";
            
            if ($api_response) {
                // تحليل الاستجابة
                $response_data = json_decode($api_response, true);
                
                if ($response_data) {
                    echo json_encode($response_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";
                    
                    // تحليل النتيجة
                    echo "=== تحليل النتيجة ===\n";
                    
                    if (isset($response_data['order_id'])) {
                        if ($response_data['order_id'] === null) {
                            echo "❌ المشكلة لا تزال موجودة: order_id = null\n";
                        } else {
                            echo "✅ مُصحح: order_id = " . $response_data['order_id'] . "\n";
                        }
                    } else {
                        echo "⚠️ order_id غير موجود في الاستجابة\n";
                    }
                    
                    if (isset($response_data['message'])) {
                        echo "📝 Message: " . $response_data['message'] . "\n";
                    }
                    
                    if (isset($response_data['errors'])) {
                        echo "❌ Errors Found:\n";
                        foreach ($response_data['errors'] as $error) {
                            echo "   - " . json_encode($error, JSON_UNESCAPED_UNICODE) . "\n";
                        }
                    }
                } else {
                    echo "Raw Response:\n{$api_response}\n\n";
                    echo "⚠️ لا يمكن تحليل الاستجابة كـ JSON\n";
                }
            } else {
                echo "❌ لا توجد استجابة\n";
            }
        }
    }
}

echo "\n=== إرشادات الاختبار اليدوي ===\n";
echo "إذا كان السيرفر لا يعمل، اختبر يدوياً:\n\n";
echo "1️⃣ من Postman:\n";
echo "   POST {$api_url}\n";
echo "   Body (JSON): " . json_encode($order_data, JSON_UNESCAPED_UNICODE) . "\n\n";
echo "2️⃣ المتوقع بعد الإصلاح:\n";
echo "   {\n";
echo "     \"message\": \"order_success\",\n";
echo "     \"order_id\": [رقم صحيح]\n";
echo "   }\n\n";
echo "3️⃣ تحقق من Order Details في الإدارة:\n";
echo "   - Total يجب أن يكون ≠ 0.00\n";
echo "   - Order ID يجب أن يطابق الاستجابة\n";

echo "\n=== انتهاء الاختبار ===\n";
?>