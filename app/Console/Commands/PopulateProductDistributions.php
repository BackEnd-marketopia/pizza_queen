<?php

namespace App\Console\Commands;

use App\Model\Product;
use App\Models\ProductDistribution;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class PopulateProductDistributions extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'products:populate-distributions';

    /**
     * The console command description.
     */
    protected $description = 'Populate product distributions for existing products';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Starting to populate product distributions...');

        try {
            DB::beginTransaction();

            // الحصول على جميع المنتجات التي لا تحتوي على distribution
            $products = Product::whereDoesntHave('distribution')->get();
            
            $this->info("Found {$products->count()} products without distribution settings.");

            if ($products->count() === 0) {
                $this->info('All products already have distribution settings.');
                return;
            }

            $progressBar = $this->output->createProgressBar($products->count());
            $progressBar->start();

            foreach ($products as $product) {
                // إنشاء distribution افتراضي - جميع الفروع
                ProductDistribution::create([
                    'product_id' => $product->id,
                    'distribution_type' => 'all_branches',
                    'branch_ids' => null
                ]);
                
                $progressBar->advance();
            }

            $progressBar->finish();
            $this->newLine();

            DB::commit();
            $this->info("✅ Successfully created distribution settings for {$products->count()} products.");
            
        } catch (\Exception $e) {
            DB::rollBack();
            $this->error('❌ Error: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }
}