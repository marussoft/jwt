<?php

namespace Marussia\Jwt\Exceptions;

class BadTokenException extends \Exception
{

    public function __construct($token)
    {
        $message = 'Токен ' . $token . ' не является MIME base64.';
    
        parent::__construct($message);
    }


} 
