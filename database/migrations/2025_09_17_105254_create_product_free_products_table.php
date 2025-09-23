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
        Schema::create('product_free_products', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('main_product_id');
            $table->unsignedBigInteger('free_product_id');
            $table->timestamps();

            $table->foreign('main_product_id')->references('id')->on('products')->onDelete('cascade');
            $table->foreign('free_product_id')->references('id')->on('products')->onDelete('cascade');
            $table->unique(['main_product_id', 'free_product_id']); // منع التكرار
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('product_free_products');
    }
};
