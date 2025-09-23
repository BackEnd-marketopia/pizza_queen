<?php

namespace App\Console\Commands;

use App\Model\Product;
use App\Models\ProductDistribution;
use Illuminate\Console\Command;

class MigrateExistingProductsToDistribution extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'products:migrate-distribution {--type=all_branches : Default distribution type}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Migrate existing products to the new distribution system';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $defaultType = $this->option('type');

        $this->info('Starting migration of existing products to distribution system...');

        // Get all products that don't have distribution yet
        $products = Product::whereDoesntHave('distribution')->get();

        $this->info("Found {$products->count()} products to migrate");

        $bar = $this->output->createProgressBar($products->count());

        foreach ($products as $product) {
            ProductDistribution::create([
                'product_id' => $product->id,
                'distribution_type' => $defaultType,
                'branch_ids' => null
            ]);

            $bar->advance();
        }

        $bar->finish();
        $this->newLine();

        $this->info('Migration completed successfully!');
        $this->info("All products now have distribution type: {$defaultType}");

        return 0;
    }
}
