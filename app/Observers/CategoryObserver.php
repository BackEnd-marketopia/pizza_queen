<?php

namespace App\Observers;

use App\Model\Category;
use Illuminate\Support\Facades\Cache;

class CategoryObserver
{
    /**
     * Handle the Category "created" event.
     */
    public function created(Category $category): void
    {
        $this->refreshCategoryCache();
    }

    /**
     * Handle the Category "updated" event.
     */
    public function updated(Category $category): void
    {
        $this->refreshCategoryCache();
    }

    /**
     * Handle the Category "deleted" event.
     */
    public function deleted(Category $category): void
    {
        $this->refreshCategoryCache();
    }

    /**
     * Handle the Category "restored" event.
     */
    public function restored(Category $category): void
    {
        $this->refreshCategoryCache();
    }

    /**
     * Handle the Category "force deleted" event.
     */
    public function forceDeleted(Category $category): void
    {
        $this->refreshCategoryCache();
    }

    private function refreshCategoryCache()
    {
        // Get supported languages from business settings
        $languagesSetting = \App\Model\BusinessSetting::where('key', 'language')->first();
        $languages = ['en', 'ar']; // Default fallback
        
        if ($languagesSetting && $languagesSetting->value) {
            $langData = json_decode($languagesSetting->value, true);
            if ($langData) {
                $languages = collect($langData)->pluck('code')->toArray();
            }
        }
        
        // Clear cache for all supported languages
        foreach ($languages as $lang) {
            Cache::forget(CATEGORIES_WITH_CHILDES . '_' . $lang);
        }
        
        // Also clear the original cache key for backward compatibility
        Cache::forget(CATEGORIES_WITH_CHILDES);
    }
}
