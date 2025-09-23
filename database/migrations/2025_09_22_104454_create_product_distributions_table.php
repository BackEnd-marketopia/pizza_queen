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
        Schema::create('product_distributions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('product_id');
            $table->json('branch_ids')->nullable(); // null = جميع الفروع، array = فروع محددة
            $table->enum('distribution_type', ['all_branches', 'selected_branches', 'main_only'])
                  ->default('all_branches');
            $table->timestamps();
            
            $table->foreign('product_id')->references('id')->on('products')->onDelete('cascade');
            $table->unique('product_id'); // كل منتج له توزيع واحد فقط
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('product_distributions');
    }
};
