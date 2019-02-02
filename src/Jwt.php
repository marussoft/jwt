<?php

declare(strict_types=1);

namespace Marussia\Jwt;

use Marussia\Jwt\Exception\BadTokenException as BadTokenException;

class Jwt
{
    // Подпись
    private $signature;

    public function __construct(string $signature)
    {
        $this->signature = $signature;
    }
    
    // Проверяет валидность токена
    private function isValidToken(string $uid) : bool
    {
        $token = base64_decode($uid);
        
        if ($token === false) {
            throw new BadTokenException($token);
        }
        
        $segments explode('.', $token);

        $header = json_decode($segments[0], true);
        
        $payload = json_decode($segments[1], true);
        
        $hash = hash('sha512', $header . $payload . $this->signature);
        
        if ($hash === $segments[2]) {
            return true;
        }
        
        return false;
    }
    
    // Возвращает новый токен
    public function getToken(array $data) : string
    {
        $header = json_encode(['alg' => 'HS512', 'exp' => 86400]);
        
        $payload = json_encode($data, JSON_UNESCAPED_UNICODE);
        
        $hash = hash('sha512', $header . $payload . $this->signature);
        
        return base64_encode($header . '.' . $payload . '.' . $hash);
    }
    
    public function checkExpireToken(string $uid) : bool
    {
    
    }
    
    public function checkRefreshToken(string $ref_token) : bool
    {
    
    }
    
    public function checkExpireRefreshToken(string $ref_token) : bool
    {
    
    }
    
    public function getRefreshToken() : string
    {
    
    }
}
