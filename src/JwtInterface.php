<?php

namespace Marussia\Jwt;

interface JwtInterface
{
    // Проверяет валидность токена
    public function isValidToken() : bool;
    
    // Возвращает новый токен
    public function getToken(array $data) : string;

}
 
