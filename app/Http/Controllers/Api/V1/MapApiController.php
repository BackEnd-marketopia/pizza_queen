<?php

namespace App\Http\Controllers\Api\V1;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;

class MapApiController extends Controller
{
    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function placeApiAutoComplete(Request $request): mixed
    {
        //dd( '3443');
        //dd( $request);

        $validator = Validator::make($request->all(), [
            'search_text' => 'required',
        ]);
        //dd( $validator);
        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
        // //dd( 'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=' . $request['search_text'] . '&latlng=' . $request['latlng'] .'&key=' . $apiKey);
        // //$response = Http::get('https://maps.googleapis.com/maps/api/place/autocomplete/json?input=' . $request['search_text'] . '&latlng=' . $request['latlng'] .'&key=' . $apiKey);
        // $response = Http::get('http://maps.googleapis.com/maps/api/place/autocomplete/json?input=%D8%A7&latlng=31.2496187,29.9717766&key=AIzaSyA5SdEf1xK-wJHb0lCIzYycsFQlS5-tYpk' . $apiKey);
        //         dd( $response);

             try {
                $response = Http::withOptions(['verify' => false])->get('https://maps.googleapis.com/maps/api/place/autocomplete/json?input=' . $request['search_text'] . '&components=country:eg&key=' . $apiKey);
                   //  dd('asdasds');

                  // dd($response->body());
                  //return $response->body();
                   return $response->json();
                } catch (\Exception $e) {
                    Log::error('Error fetching data: ' . $e->getMessage()); // Use Log facade
                    return response()->json(['error' => 'Failed to fetch data'], 500);
                }
                

        return response()->json();
    }

    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function distanceApi(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'origin_lat' => 'required',
            'origin_lng' => 'required',
            'destination_lat' => 'required',
            'destination_lng' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
        $response = Http::get('https://maps.googleapis.com/maps/api/distancematrix/json?origins=' . $request['origin_lat'] . ',' . $request['origin_lng'] . '&destinations=' . $request['destination_lat'] . ',' . $request['destination_lng'] . '&key=' . $apiKey);

        return $response->json();
    }

    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function placeApiDetails(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'placeid' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');

        try {
            $response = Http::withOptions(['verify' => false])->get('https://maps.googleapis.com/maps/api/place/details/json?placeid=' . $request['placeid'] . '&key=' . $apiKey);
               //  dd('asdasds');

              // dd($response->body());
              //return $response->body();
               return $response->json();
            } catch (\Exception $e) {
                Log::error('Error fetching data: ' . $e->getMessage()); // Use Log facade
                return response()->json(['error' => 'Failed to fetch data'], 500);
            }
            

       // $response = Http::get('https://maps.googleapis.com/maps/api/place/details/json?placeid=' . $request['placeid'] . '&key=' . $apiKey);

       // return $response->json();
    }

    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function geocodeApi(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'lat' => 'required',
            'lng' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
        $response = Http::get('https://maps.googleapis.com/maps/api/geocode/json?latlng=' . $request->lat . ',' . $request->lng . '&key=' . $apiKey);
        dd( $response);

        return $response->json();
    }
}


