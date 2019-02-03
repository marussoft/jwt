<?php

declare(strict_types=1);

namespace Marussia\Jwt;

use Marussia\Jwt\Exception\BadTokenException as BadTokenException;
use Marussia\Jwt\JwtInterface as JwtInterface;

class Jwt implements JwtInterface
{
    // Подпись
    private $key;
    
    private $payload;
    
    private $jwt;

    public function __construct(string $key)
    {
        $this->key = $key;
    }
    
    public function setJwt(string $jwt)
    {
        $this->jwt = $jwt;
    }
    
    // Проверяет валидность токена
    private function isValidToken() : bool
    {
        $token = base64_decode($this->jwt);
        
        if ($token === false) {
            throw new BadTokenException($token);
        }
        
        $segments explode('.', $token);

        $header = json_decode($segments[0], true);
        
        $this->payload = json_decode($segments[1], true);
        
        $signature = hash('sha512', $header . $this->payload . $this->key);
        
        if ($signature === $segments[2]) {
            return true;
        }
        
        return false;
    }
    
    public function getPayload()
    {
        return $this->payload;
    }
    
    // Возвращает новый токен
    public function getToken(array $data) : string
    {
        $header = json_encode(['alg' => 'HS512', 'exp' => 86400]);
        
        $payload = json_encode($data, JSON_UNESCAPED_UNICODE);
        
        $signature = hash('sha512', $header . $payload . $this->key);
        
        return base64_encode($header . '.' . $payload . '.' . $signature);
    }

}
