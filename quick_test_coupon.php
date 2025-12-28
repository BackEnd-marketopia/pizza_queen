<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>اختبار كوبون Queen30 - مباشر</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        .section { background: #f9f9f9; padding: 15px; margin: 20px 0; border-left: 4px solid #4CAF50; }
        .error { color: #f44336; font-weight: bold; }
        .success { color: #4CAF50; font-weight: bold; }
        .warning { color: #ff9800; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: right; }
        th { background: #4CAF50; color: white; }
        .highlight { background: #fffacd; font-weight: bold; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 15px; font-size: 12px; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-error { background: #f8d7da; color: #721c24; }
        .badge-warning { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 اختبار مباشر للكوبون Queen30</h1>
    <p><strong>الوقت:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
    
    <?php
    // Database connection
    $host = 'localhost';
    $dbname = 'pizza_queen'; // غير هذا لاسم قاعدة البيانات الفعلي
    $username = 'root';      // غير هذا للـ username الفعلي
    $password = '';          // غير هذا للـ password الفعلي
    
    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        echo '<div class="section">';
        echo '<span class="success">✅ تم الاتصال بقاعدة البيانات بنجاح</span>';
        echo '</div>';
        
        // Get coupon
        $stmt = $pdo->prepare("SELECT * FROM coupons WHERE code = ?");
        $stmt->execute(['Queen30']);
        $coupon = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($coupon) {
            echo '<div class="section">';
            echo '<h2>1️⃣ الكوبون موجود في قاعدة البيانات</h2>';
            
            // Check active status
            $isActive = $coupon['status'] == 1;
            $today = date('Y-m-d');
            $startOk = $coupon['start_date'] <= $today;
            $expireOk = $coupon['expire_date'] >= $today;
            $isValidDate = $startOk && $expireOk;
            $overallActive = $isActive && $isValidDate;
            
            echo '<table>';
            echo '<tr><th>الحقل</th><th>القيمة في DB</th><th>الحالة</th></tr>';
            echo '<tr><td>ID</td><td>' . $coupon['id'] . '</td><td></td></tr>';
            echo '<tr><td>Code</td><td><strong>' . $coupon['code'] . '</strong></td><td></td></tr>';
            echo '<tr><td>Title</td><td>' . $coupon['title'] . '</td><td></td></tr>';
            echo '<tr><td>Type</td><td>' . $coupon['coupon_type'] . '</td><td>' . 
                ($coupon['coupon_type'] == 'first_order' ? '<span class="badge-warning">⚠️ أول طلب فقط</span>' : '<span class="badge-success">✅ عادي</span>') . 
                '</td></tr>';
            
            echo '<tr class="highlight"><td><strong>Discount (الخصم)</strong></td><td><strong>' . $coupon['discount'] . '</strong></td><td></td></tr>';
            echo '<tr class="highlight"><td><strong>Discount Type</strong></td><td><strong>' . $coupon['discount_type'] . '</strong></td><td>' .
                ($coupon['discount_type'] == 'percent' ? '📊 نسبة مئوية' : '💰 مبلغ ثابت') .
                '</td></tr>';
            
            echo '<tr><td>Min Purchase</td><td>' . $coupon['min_purchase'] . '</td><td>' .
                ($coupon['min_purchase'] > 0 ? '<span class="warning">⚠️ يتطلب ' . $coupon['min_purchase'] . ' جنيه على الأقل</span>' : '<span class="success">✅ لا يوجد حد أدنى</span>') .
                '</td></tr>';
            echo '<tr><td>Max Discount</td><td>' . $coupon['max_discount'] . '</td><td></td></tr>';
            echo '<tr><td>Limit</td><td>' . ($coupon['limit'] ?? 'غير محدود') . '</td><td></td></tr>';
            
            echo '<tr><td>Status</td><td>' . $coupon['status'] . '</td><td>' .
                ($isActive ? '<span class="success">✅ نشط</span>' : '<span class="error">❌ غير نشط</span>') .
                '</td></tr>';
            echo '<tr><td>Start Date</td><td>' . $coupon['start_date'] . '</td><td>' .
                ($startOk ? '<span class="success">✅ بدأ</span>' : '<span class="error">❌ لم يبدأ</span>') .
                '</td></tr>';
            echo '<tr><td>Expire Date</td><td>' . $coupon['expire_date'] . '</td><td>' .
                ($expireOk ? '<span class="success">✅ صالح</span>' : '<span class="error">❌ منتهي</span>') .
                '</td></tr>';
            
            echo '</table>';
            
            if ($overallActive) {
                echo '<p class="success">✅ الكوبون نشط وصالح للاستخدام</p>';
            } else {
                echo '<p class="error">❌ الكوبون غير نشط:</p><ul>';
                if (!$isActive) echo '<li>Status = 0 (غير مفعل)</li>';
                if (!$startOk) echo '<li>لم يبدأ بعد</li>';
                if (!$expireOk) echo '<li>منتهي الصلاحية</li>';
                echo '</ul>';
            }
            
            echo '</div>';
            
            // Calculate discount
            echo '<div class="section">';
            echo '<h2>2️⃣ حساب الخصم لـ Subtotal = 226.75 جنيه</h2>';
            
            $testSubtotal = 226.75;
            
            echo '<table>';
            echo '<tr><th>الخطوة</th><th>الحساب</th><th>النتيجة</th></tr>';
            
            // Check min purchase
            $meetsMin = $testSubtotal >= $coupon['min_purchase'];
            echo '<tr><td>1. فحص الحد الأدنى</td><td>' . $testSubtotal . ' >= ' . $coupon['min_purchase'] . '</td><td>' .
                ($meetsMin ? '<span class="success">✅ نعم</span>' : '<span class="error">❌ لا</span>') .
                '</td></tr>';
            
            if ($meetsMin) {
                $discount = 0;
                $calculation = '';
                
                if ($coupon['discount_type'] == 'percent') {
                    $rawDiscount = ($testSubtotal * $coupon['discount']) / 100;
                    $calculation = "({$testSubtotal} × {$coupon['discount']}) ÷ 100 = " . number_format($rawDiscount, 2);
                    
                    if ($rawDiscount > $coupon['max_discount']) {
                        $discount = $coupon['max_discount'];
                        $calculation .= " → Max: {$coupon['max_discount']}";
                    } else {
                        $discount = $rawDiscount;
                    }
                } else {
                    $discount = $coupon['discount'];
                    $calculation = "مبلغ ثابت = {$discount}";
                }
                
                echo '<tr class="highlight"><td><strong>2. حساب الخصم</strong></td><td><strong>' . $calculation . '</strong></td><td><strong class="success">' . number_format($discount, 2) . ' جنيه</strong></td></tr>';
                
                $finalTotal = $testSubtotal - $discount + 45; // + delivery
                echo '<tr><td>3. المجموع النهائي</td><td>' . $testSubtotal . ' - ' . number_format($discount, 2) . ' + 45 (توصيل)</td><td><strong>' . number_format($finalTotal, 2) . ' جنيه</strong></td></tr>';
                
                echo '</table>';
                
                echo '<div style="background:#d4edda;padding:15px;border-radius:5px;margin-top:20px">';
                echo '<p style="margin:0;font-size:18px"><strong>💰 الخصم المتوقع: ' . number_format($discount, 2) . ' جنيه</strong></p>';
                echo '<p style="margin:5px 0 0 0;color:#666">من أصل ' . $testSubtotal . ' جنيه</p>';
                echo '</div>';
                
            } else {
                echo '<tr><td colspan="3" class="error">❌ الـ Subtotal أقل من الحد الأدنى المطلوب</td></tr>';
                echo '</table>';
            }
            
            echo '</div>';
            
            // Check Order #536389
            echo '<div class="section">';
            echo '<h2>3️⃣ فحص Order #536389</h2>';
            
            $stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
            $stmt->execute([536389]);
            $order = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($order) {
                echo '<table>';
                echo '<tr><th>الحقل</th><th>القيمة</th></tr>';
                echo '<tr><td>Order ID</td><td>' . $order['id'] . '</td></tr>';
                echo '<tr><td>User ID</td><td>' . $order['user_id'] . '</td></tr>';
                echo '<tr><td>Coupon Code</td><td><strong>' . ($order['coupon_code'] ?? 'لا يوجد') . '</strong></td></tr>';
                echo '<tr class="highlight"><td><strong>Coupon Discount Amount</strong></td><td><strong class="' . ($order['coupon_discount_amount'] > 0 ? 'success' : 'error') . '">' . $order['coupon_discount_amount'] . ' جنيه</strong></td></tr>';
                echo '<tr><td>Order Amount</td><td>' . $order['order_amount'] . ' جنيه</td></tr>';
                echo '</table>';
                
                // Check previous orders
                if ($coupon['coupon_type'] == 'first_order') {
                    $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM orders WHERE user_id = ? AND id < ? AND is_guest = 0");
                    $stmt->execute([$order['user_id'], 536389]);
                    $prevCount = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
                    
                    echo '<p><strong>عدد الطلبات السابقة:</strong> ' . $prevCount . '</p>';
                    
                    if ($prevCount == 0) {
                        echo '<p class="success">✅ هذا أول طلب للعميل - كوبون first_order يجب أن يعمل</p>';
                    } else {
                        echo '<p class="error">❌ العميل عنده ' . $prevCount . ' طلب سابق - كوبون first_order لن يعمل</p>';
                        echo '<p class="warning">⚠️ <strong>الحل:</strong> غير نوع الكوبون إلى <code>default</code> بدلاً من <code>first_order</code></p>';
                        echo '<p><code>UPDATE coupons SET coupon_type = \'default\' WHERE code = \'Queen30\';</code></p>';
                    }
                }
                
            } else {
                echo '<p class="error">Order #536389 غير موجود</p>';
            }
            
            echo '</div>';
            
        } else {
            echo '<div class="section">';
            echo '<p class="error">❌ الكوبون غير موجود في قاعدة البيانات!</p>';
            echo '</div>';
        }
        
    } catch (PDOException $e) {
        echo '<div class="section">';
        echo '<p class="error">❌ خطأ في الاتصال بقاعدة البيانات:</p>';
        echo '<p>' . $e->getMessage() . '</p>';
        echo '<p><strong>الحل:</strong> عدل بيانات الاتصال في بداية الملف (السطور 23-26)</p>';
        echo '</div>';
    }
    ?>
    
    <div class="section" style="background:#fff3cd;border-left-color:#ff9800">
        <h3>📝 ملاحظات مهمة</h3>
        <ul>
            <li>إذا كان الكوبون من نوع <code>first_order</code> والعميل عنده طلبات سابقة، لن يعمل الخصم</li>
            <li>تأكد من أن <code>status = 1</code> في قاعدة البيانات</li>
            <li>تأكد من أن التواريخ صالحة</li>
            <li>تحقق من logs في <code>storage/logs/laravel.log</code> للمزيد من التفاصيل</li>
        </ul>
    </div>
    
</div>
</body>
</html>
