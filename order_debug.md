# مشكلة حساب الطلبات - Order Calculation Issue

## المشكلة
هناك اختلاف بين المبلغ المرسل من التطبيق والمبلغ المحسوب في الفاتورة:

### البيانات المرسلة من التطبيق:
- `order_amount`: 293.25 ج.م
- `delivery_charge`: (محسوب منفصلاً) 45.00 ج.م  
- المتوقع الإجمالي: 338.25 ج.م

### البيانات في الفاتورة:
- Items Price: 221.75 ج.م
- Tax/VAT: 0.00 ج.م
- Addon Cost: 27.75 ج.م
- Subtotal: 249.50 ج.م
- Delivery Fee: 45.00 ج.م
- **Total: 294.50 ج.م**

## التغييرات المُطبقة:

### 1. تصحيح حساب المنتجات المجانية (Free Products)
```php
// قبل التصحيح: كان يتم حساب السعر الأساسي + variation للمنتجات المجانية
// بعد التصحيح: يتم حساب variation + addons فقط للمنتجات المجانية
if (isset($c['is_free']) && $c['is_free']) {
    $price = $variation_data['price']; // فقط سعر variation
    $price += $total_addon_price; // إضافة سعر addons
}
```

### 2. تصحيح حساب الإجمالي في الفاتورة
```php
// قبل التصحيح: 
$subTotal + $del_c + $totalTax + $addOnsCost - $order['coupon_discount_amount'] - $order['extra_discount'] + $add_ons_tax_cost

// بعد التصحيح:
$order['order_amount'] + $del_c - $order['coupon_discount_amount'] - $order['extra_discount']
```

### 3. إضافة logging للتتبع
تم إضافة logging في OrderController لتتبع تفاصيل الحسابات.

## اختبار الحل:

للتأكد من نجاح الحل:
1. قم بتجربة طلب جديد من التطبيق
2. تحقق من logs في `storage/logs/laravel.log`
3. قارن بين order_amount المرسل والإجمالي في الفاتورة

## ملاحظات:
- المشكلة كانت في معالجة المنتجات المجانية وعدم حساب addon costs بشكل صحيح
- التطبيق يحسب order_amount بدون delivery_charge، والذي يُضاف منفصلاً
- الحل يضمن التطابق بين المبلغ المرسل والمعروض في الفاتورة