<?php

declare(strict_types=1);

namespace Marussia\Jwt;

use Marussia\Jwt\Exception\BadTokenException as BadTokenException;
use Marussia\Jwt\JwtInterface as JwtInterface;

class Jwt implements JwtInterface
{
    // Подпись
    private $key;
    
    private $segments;
    
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
    public function isValidToken() : bool
    {
        $token = base64_decode($this->jwt);
        
        if ($token === false) {
            throw new BadTokenException($token);
        }
        
        $this->segments = explode('.', $token);

        $signature = hash('sha512', $this->segments[0] . $this->segments[1] . $this->key);
        
        if ($signature === $this->segments[2]) {
            return true;
        }
        
        return false;
    }
    
    public function getPayload()
    {
        return json_decode($this->segments[1], true);
    }
    
    public function getHeader()
    {
        return json_decode($this->segments[0], true);
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
