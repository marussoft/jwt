<?php

declare(strict_types=1);

namespace Marussia\Jwt;

use Marussia\Jwt\Exceptions\BadTokenException;

class Jwt
{
    // Подпись
    private $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }
    
    // Проверяет валидность токена
    public function isValidToken(string $jwt) : bool
    {
        $segments = $this->parse($jwt);

        $signature = hash('sha512', $segments[0] . $segments[1] . $this->key);
        
        return hash_equals($signature, $segments[2]);
    }
    
    public function getPayload(string $jwt)
    {
        $segments = $this->parse($jwt);
    
        return json_decode($segments[1], true);
    }
    
    public function getHeader(string $jwt) : array
    {
        $segments = $this->parse($jwt);
        
        return json_decode($segments[0], true);
    }
    
    // Возвращает новый токен
    public function getToken(array $data) : string
    {
        $header = json_encode(['alg' => 'HS512', 'exp' => 86400]);
        
        $payload = json_encode($data, JSON_UNESCAPED_UNICODE);
        
        $signature = hash('sha512', $header . $payload . $this->key);
        
        return base64_encode($header . '.' . $payload . '.' . $signature);
    }

    private function parse(string $jwt) : array
    {
        $token = base64_decode($jwt, true);
        
        if ($token === false) {
            throw new BadTokenException($token);
        }

        return explode('.', $token);
    }
}
