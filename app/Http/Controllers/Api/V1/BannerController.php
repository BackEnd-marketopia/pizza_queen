<?php

namespace App\Http\Controllers\Api\V1;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use App\Model\Banner;
use Illuminate\Http\JsonResponse;
use Carbon\Carbon;

class BannerController extends Controller
{
    public function __construct(
        private Banner $banner
    ) {}

    /**
     * @return JsonResponse
     */
    public function getBanners(): JsonResponse
    {
        $banners = $this->banner->with(['product.rating', 'product.branch_product'])->active()->get();
        foreach ($banners as $banner) {
            $banner['product'] = isset($banner['product']) ? Helpers::product_data_formatting($banner['product']) : null;
            $banner['product'] = isset($banner['product']) ? $this->is_available($banner['product']) :  null;
        }

        return response()->json($banners, 200);
    }

    public static function is_available(array $products): array
    {
        $now = now('Africa/Cairo');

        foreach ($products as &$product) {
            if (isset($product['item_type']) && $product['item_type'] === 'set_menu') {
                $product['is_available'] = true;
                continue;
            }

            $isAvailable = true;

            if (!empty($product['available_time_starts']) && !empty($product['available_time_ends'])) {
                $startTime = Carbon::parse($product['available_time_starts'])->setDate($now->year, $now->month, $now->day);
                $endTime = Carbon::parse($product['available_time_ends'])->setDate($now->year, $now->month, $now->day);

                if ($startTime->greaterThan($endTime)) {
                    $endTime->addDay();
                }

                $isAvailable = $now->between($startTime, $endTime, true);
            }


            if (!empty($product['available_date_starts']) && !empty($product['available_date_ends'])) {
                $startDate = Carbon::parse($product['available_date_starts']);
                $endDate = Carbon::parse($product['available_date_ends']);

                $isAvailable = $now->between($startDate, $endDate);
            }

            $product['is_available'] = $isAvailable;
        }
        unset($product);

        return $products;
    }
}
