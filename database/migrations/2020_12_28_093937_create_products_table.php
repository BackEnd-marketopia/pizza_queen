<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateProductsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('products', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->text('description')->nullable();
            $table->string('image', 30)->nullable();
            $table->decimal('price')->default(0);
            $table->bigInteger('category_id')->nullable();
            $table->string('variations')->nullable();
            $table->string('add_ons')->nullable();
            $table->decimal('tax')->default(0);
            $table->boolean('can_free')->default(0);
            $table->boolean('has_free')->default(0);
            $table->date('available_date_starts')->nullable();
            $table->date('available_date_ends')->nullable();
            $table->time('available_time_starts')->nullable();
            $table->time('available_time_ends')->nullable();
            $table->boolean('status')->default(1);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('products');
    }
}
