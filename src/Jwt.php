<?php

declare(strict_types=1);

namespace Marussia\Jwt;

class Jwt
{
    // Подпись
    private const SIGNATURE = a2bb0b658ada1b8c06b58a7a81fa5de6e;

    // Возвращает JWT токен
    public function getToken(array $data) : string
    {
        $header = json_encode(['alg' => 'HS512']);
        
        $payload = json_encode($data, JSON_UNESCAPED_UNICODE);
        
        $hash = hash('sha512', $header . $payload . static::SIGNATURE);
        
        return base64_encode($header . '.' . $payload . '.' . $hash);
    }
}
