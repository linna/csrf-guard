<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\CsrfGuard\Provider;

use Linna\CsrfGuard\Exception\BadExpireException;
use Linna\CsrfGuard\Exception\BadExpireTrait;

/**
 * Csrf HMAC Based Token Pattern Provider.
 *
 * It use hash_hmac with sha3-384 algorithm.
 */
class HmacTokenProvider implements TokenProviderInterface
{
    use BadExpireTrait;

    /**
     * @var string $key Secret key for the hmac
     */
    private string $key = '';

    /**
     * @var string $value Value will be hashed inside token
     */
    private string $value = '';

    /**
     * @var int $expire Token validity in seconds, default 600 -> 10 minutes
     */
    private int $expire = 0;

    /**
     * Class constructor.
     *
     * @param string $value     Value will be hashed inside token
     * @param string $key       Secret key for the hmac
     * @param int    $expire    Token validity in seconds, default 600 -> 10 minutes
     *
     * @throws BadExpireException If $expire is less than 0 and greater than 86400
     */
    public function __construct(string $value, string $key, int $expire = 600)
    {
        // from BadExpireTrait
        /** @throws BadExpireException */
        $this->checkBadExpire($expire);

        $this->key = $key;
        $this->value = $value;
        $this->expire = $expire;
    }

    /**
     * Return new Hmac Token.
     *
     * @return string
     */
    public function getToken(): string
    {
        //get the time for the token
        $time = \base_convert((string) \time(), 10, 16);
        //random bytes for avoid to wait one second to get a different token
        $random = \bin2hex(\random_bytes(2));

        //return the token
        return \hash_hmac('sha3-384', $this->value.$time.$random, $this->key).$time.$random;
    }

    /**
     * Validate Hmac Token.
     *
     * @param string $token Token must be validated.
     *
     * @return bool
     */
    public function validate(string $token): bool
    {
        //check for void token
        if ($token === "") {
            return false;
        }

        //hmac present in token
        $hmac_token = \substr($token, 0, 96);
        //token time
        $time = \substr($token, 96, 8);
        //random value
        $random = \substr($token, 104);

        //hmac generate locally with token time
        $hmac_local = \hash_hmac('sha3-384', $this->value.$time.$random, $this->key);

        //hmac check in constant time
        if (!\hash_equals($hmac_local, $hmac_token)) {
            return false;
        }

        //timestamp from token time
        $timestamp = (int) \base_convert($time, 16, 10);

        //token expiration check
        if ($timestamp + $this->expire < \time()) {
            return false;
        }

        return true;
    }
}
