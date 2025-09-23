<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Model\Product;
use App\Model\Branch;
use App\Models\ProductDistribution;
use App\Model\ProductByBranch;
use App\CentralLogics\Helpers;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\View\View;
use Illuminate\Support\Facades\Log;

class ProductDistributionController extends Controller
{
    /**
     * عرض صفحة إدارة التوزيعات
     */
    public function index(): View
    {
        $products = Product::with(['distribution', 'main_branch_product'])
                          ->orderBy('id', 'desc')
                          ->paginate(Helpers::getPagination());

        $branches = Branch::active()->get();

        return view('admin-views.product.distributions', compact('products', 'branches'));
    }

    /**
     * تحديث توزيع منتج معين
     */
    public function update(Request $request): JsonResponse
    {
        $request->validate([
            'product_id' => 'required|exists:products,id',
            'distribution_type' => 'required|in:all_branches,selected_branches,main_only',
            'branch_ids' => 'nullable|array',
            'branch_ids.*' => 'exists:branches,id'
        ]);

        try {
            // Log the request data for debugging
            Log::info('Product Distribution Update Request:', [
                'product_id' => $request->product_id,
                'distribution_type' => $request->distribution_type,
                'branch_ids' => $request->branch_ids,
                'all_request' => $request->all()
            ]);

            // إنشاء أو تحديث التوزيع
            $distribution = ProductDistribution::updateOrCreate(
                ['product_id' => $request->product_id],
                [
                    'distribution_type' => $request->distribution_type,
                    'branch_ids' => $request->distribution_type === 'selected_branches' ? $request->branch_ids : null
                ]
            );

            // تأكد من الحفظ
            $distribution->refresh();
            
            Log::info('Distribution after save:', [
                'id' => $distribution->id,
                'product_id' => $distribution->product_id,
                'distribution_type' => $distribution->distribution_type,
                'branch_ids' => $distribution->branch_ids,
                'updated_at' => $distribution->updated_at
            ]);

            // تحديث المنتجات في الفروع حسب التوزيع الجديد
            $this->syncProductToBranches($request->product_id, $request->distribution_type, $request->branch_ids);

            return response()->json([
                'success' => true,
                'message' => translate('Product distribution updated successfully')
            ]);

        } catch (\Exception $e) {
            Log::error('Product Distribution Update Error:', ['error' => $e->getMessage()]);
            return response()->json([
                'success' => false,
                'message' => translate('Failed to update distribution')
            ], 500);
        }
    }

    /**
     * الحصول على بيانات توزيع منتج معين
     */
    public function show($productId): JsonResponse
    {
        $distribution = ProductDistribution::where('product_id', $productId)->first();

        return response()->json([
            'distribution' => $distribution
        ]);
    }

    /**
     * تطبيق التوزيع على جميع المنتجات الموجودة
     */
    public function applyToAll(Request $request): JsonResponse
    {
        $request->validate([
            'distribution_type' => 'required|in:all_branches,selected_branches,main_only',
            'branch_ids' => 'nullable|array'
        ]);

        try {
            $products = Product::all();

            foreach ($products as $product) {
                ProductDistribution::updateOrCreate(
                    ['product_id' => $product->id],
                    [
                        'distribution_type' => $request->distribution_type,
                        'branch_ids' => $request->distribution_type === 'selected_branches' ? $request->branch_ids : null
                    ]
                );

                $this->syncProductToBranches($product->id, $request->distribution_type, $request->branch_ids);
            }

            return response()->json([
                'success' => true,
                'message' => translate('Distribution applied to all products successfully')
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => translate('Failed to apply distribution')
            ], 500);
        }
    }

    /**
     * مزامنة المنتج مع الفروع حسب نوع التوزيع
     */
    private function syncProductToBranches($productId, $distributionType, $branchIds = null)
    {
        Log::info('Sync Product to Branches:', [
            'product_id' => $productId,
            'distribution_type' => $distributionType,
            'branch_ids' => $branchIds
        ]);

        // الحصول على بيانات المنتج من الفرع الرئيسي قبل الحذف
        $mainBranchProduct = ProductByBranch::where('product_id', $productId)
                                           ->where('branch_id', 1)->first();

        if (!$mainBranchProduct) {
            // إذا لم يكن موجود في الفرع الرئيسي، نبحث عن أي فرع آخر
            $mainBranchProduct = ProductByBranch::where('product_id', $productId)->first();
        }

        // إذا لم نجد أي بيانات، نحصل على بيانات المنتج الأساسية
        $baseProduct = Product::find($productId);
        if (!$mainBranchProduct && !$baseProduct) {
            Log::warning("No product data found for product {$productId}");
            return;
        }

        // إنشاء البيانات الافتراضية
        $defaultData = [
            'price' => $mainBranchProduct ? $mainBranchProduct->price : ($baseProduct->price ?? 100),
            'discount_type' => $mainBranchProduct ? $mainBranchProduct->discount_type : 'percentage',
            'discount' => $mainBranchProduct ? $mainBranchProduct->discount : 0,
            'is_available' => 1,
            'variations' => $mainBranchProduct ? $mainBranchProduct->variations : '[]',
            'stock_type' => $mainBranchProduct ? $mainBranchProduct->stock_type : 'unlimited',
            'stock' => $mainBranchProduct ? $mainBranchProduct->stock : 0,
        ];

        // حذف المنتج من جميع الفروع
        $deleted = ProductByBranch::where('product_id', $productId)->delete();
        Log::info("Deleted {$deleted} product-branch records for product {$productId}");

        $branches = Branch::active()->get();
        Log::info("Found {$branches->count()} active branches");

        if ($distributionType === 'all_branches') {
            // إضافة لجميع الفروع
            foreach ($branches as $branch) {
                ProductByBranch::create(array_merge([
                    'product_id' => $productId,
                    'branch_id' => $branch->id,
                ], $defaultData));
            }
            Log::info("Added product {$productId} to all {$branches->count()} branches");
        } elseif ($distributionType === 'selected_branches' && $branchIds) {
            // إضافة للفروع المحددة فقط
            foreach ($branchIds as $branchId) {
                ProductByBranch::create(array_merge([
                    'product_id' => $productId,
                    'branch_id' => $branchId,
                ], $defaultData));
            }
            Log::info("Added product {$productId} to selected branches: " . implode(', ', $branchIds));
        } elseif ($distributionType === 'main_only') {
            // إضافة للفرع الرئيسي فقط
            ProductByBranch::create(array_merge([
                'product_id' => $productId,
                'branch_id' => 1,
            ], $defaultData));
            Log::info("Added product {$productId} to main branch only");
        }
    }
}
