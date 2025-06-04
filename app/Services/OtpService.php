<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class OtpService
{
    protected string $baseUrl;
    protected array  $credentials;

    public function __construct()
    {
        $this->baseUrl = 'https://smsmisr.com/api/OTP/';
        $this->credentials = [
            'username' => env('SMSMISR_OTP_USERNAME'),
            'password' => env('SMSMISR_OTP_PASSWORD'),
        ];
    }

    public function generateAndSend(string $phone)
    {
        $code = random_int(100000, 999999);

        $payload = array_merge($this->credentials, [
            'mobile'      => substr($phone, -11),
            'sender'      => env('SMSMISR_OTP_SENDER'),
            'template'    => env('SMSMISR_OTP_TEMPLATE_ID'),
            'username'    => env('SMSMISR_OTP_USERNAME'),
            'password'    => env('SMSMISR_OTP_PASSWORD'),
            'language'    => '1',
            'environment' => '1',
            'otp'         => $code,
        ]);

        $response = Http::asForm()
            ->post($this->baseUrl, $payload);

        cache()->put('otp_' . $phone . '_' . $code, $code, 5 * 60);

        if (isset($response['Code']) && $response['Code'] == 4901) {
            return ['success' => true, 'code' => $code];
        } else {
            return ['success' => false, 'code' => $response['code']];
        }
    }
    public function verify(string $phone, string $code)
    {
        $cache = cache()->get('otp_' . $phone . '_' . $code);

        if ($cache === null || $cache != $code)
            return false;

        return true;
    }
}
