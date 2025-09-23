<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ProductDistribution extends Model
{
    use HasFactory;

    protected $fillable = [
        'product_id',
        'branch_ids',
        'distribution_type'
    ];

    protected $casts = [
        'branch_ids' => 'array',
        'product_id' => 'integer'
    ];

    public function product(): BelongsTo
    {
        return $this->belongsTo(\App\Model\Product::class);
    }

    /**
     * التحقق من إمكانية عرض المنتج في فرع معين
     */
    public function isAvailableForBranch(int $branchId): bool
    {
        if ($this->distribution_type === 'all_branches') {
            return true;
        }

        if ($this->distribution_type === 'main_only') {
            return $branchId === 1;
        }

        if ($this->distribution_type === 'selected_branches') {
            return in_array($branchId, $this->branch_ids ?? []);
        }

        return false;
    }
}
