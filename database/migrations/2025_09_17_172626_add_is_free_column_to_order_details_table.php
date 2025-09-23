<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('order_details', function (Blueprint $table) {
            $table->boolean('is_free')->default(false)->comment('Indicates if this is a free product');
            $table->bigInteger('free_for_product_id')->nullable()->comment('Original product ID this free product belongs to');
            
            // Add index for better performance
            $table->index(['is_free', 'free_for_product_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('order_details', function (Blueprint $table) {
            $table->dropIndex(['is_free', 'free_for_product_id']);
            $table->dropColumn(['is_free', 'free_for_product_id']);
        });
    }
};
