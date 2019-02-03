<?php

declare(strict_types=1);

namespace Marussia\Jwt;

use Marussia\Jwt\Exception\BadTokenException as BadTokenException;
use Marussia\Jwt\JwtInterface as JwtInterface;

interface
{
    // Подпись
    private $signature;

    public function __construct(string $key)
    
    // Проверяет валидность токена
    private function isValidToken(string $jwt) : bool
    
    // Возвращает новый токен
    public function getToken(array $data) : string

}
 
