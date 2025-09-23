<?php

namespace Database\Seeders;

use App\Model\Product;
use App\Models\ProductDistribution;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class ProductDistributionSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // تنظيف الجدول أولاً
        DB::table('product_distributions')->truncate();

        // الحصول على جميع المنتجات
        $products = Product::all();

        foreach ($products as $product) {
            ProductDistribution::create([
                'product_id' => $product->id,
                'distribution_type' => 'all_branches', // افتراضي: متاح لجميع الفروع
                'branch_ids' => null // null يعني جميع الفروع
            ]);
        }

        $this->command->info("✅ Created distribution settings for {$products->count()} products.");
    }
}