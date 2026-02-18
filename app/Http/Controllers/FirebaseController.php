<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class FirebaseController extends Controller
{
    protected $messaging;

    public function __construct()
    {
        $this->messaging = app('firebase.messaging');
    }

    public function subscribeToTopic(Request $request)
    {
        $request->validate([
            'token' => 'required|string',
            'topic' => 'required|string',
        ]);

        $token = $request->input('token');
        $topic = $request->input('topic');

        try {
            if($this->messaging){
                $this->messaging->subscribeToTopic($topic, $token);
                return response()->json(['message' => 'Successfully subscribed to topic'], 200);
            }
            Log::warning('FCM subscribe failed: firebase.messaging service unavailable', [
                'topic' => $topic,
            ]);
            return response()->json(['message' => 'Unauthorized'], 401);
        } catch (\Exception $e) {
            Log::error('FCM subscribe exception', [
                'topic' => $topic,
                'error' => $e->getMessage(),
            ]);
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }
}
