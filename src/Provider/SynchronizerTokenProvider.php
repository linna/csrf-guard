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
use Linna\CsrfGuard\Exception\BadStorageSizeException;
use Linna\CsrfGuard\Exception\BadTokenLenghtException;

/**
 * Syncronizer token provider
 */
class SynchronizerTokenProvider implements TokenProviderInterface
{
    /**
     * @var string CSRF_TOKEN_STORAGE Token storage key name in session array
     */
    private const CSRF_TOKEN_STORAGE = 'csrf_syncronizer_token';

    /**
     * @var string $sessionId Session id of the current session
     */
    private string $sessionId = '';

    /**
     * @var $expire Token validity in seconds, default 600 -> 10 minutes
     */
    private int $expire = 0;

    /**
     * @var $tokenLenght Token lenght in chars
     */
    private int $tokenLenght = 32;

    /**
     * @var $storageSize Maximum token nonces stored in session
     */
    private int $storageSize = 10;

    /**
     * Class constructor.
     *
     * @param string $sessionId   Session id of the current session
     * @param int    $expire      Token validity in seconds, default 600 -> 10 minutes
     * @param int    $storageSize Maximum token nonces stored in session
     * @param int    $tokenLenght Token lenght in bytes
     *
     * @throws BadExpireException      If $expire is less than 0 and greater than 86400
     * @throws BadStorageSizeException If $storageSize is less than 2 and greater than 64
     * @throws BadTokenLenghtException If $tokenLenght is less than 16 and greater than 128
     */
    public function __construct(string $sessionId, int $expire = 600, int $storageSize = 10, int $tokenLenght = 32)
    {
        // expire maximum tim is one day
        if ($expire < 0 || $expire > 86400) {
            throw new BadExpireException('Expire time must be between 0 and PHP_INT_MAX');
        }

        if ($storageSize < 2 || $storageSize > 128) {
            throw new BadStorageSizeException('Storage size must be between 2 and 128');
        }

        if ($tokenLenght < 16 || $tokenLenght > 128) {
            throw new BadTokenLenghtException('Token lenght must be between 16 and 128');
        }

        $this->sessionId = $sessionId;
        $this->expire = $expire;
        $this->tokenLenght = $tokenLenght;
        $this->storageSize = $storageSize;

        //if no nonce stored, initialize the session storage
        $_SESSION[static::CSRF_TOKEN_STORAGE] ??= [];
    }

    /**
     * Return new Synchronizer based Token.
     *
     * @return string A hex token
     */
    public function getToken(): string
    {
        //generate new nonce
        $token = \bin2hex(\random_bytes($this->tokenLenght));
        $time = \base_convert((string) \time(), 10, 16);

        //store new nonce
        $_SESSION[static::CSRF_TOKEN_STORAGE][] = $token.$time;

        //check if the storage is growt beyond the maximun size
        if (\count($_SESSION[static::CSRF_TOKEN_STORAGE]) > $this->storageSize) {
            //remove the oldest stores nonce
            \array_shift($_SESSION[static::CSRF_TOKEN_STORAGE]);
        }

        return $token;
    }

    /**
     * Validate Synchronizer based Token.
     *
     * @param string $token Token must be validated, hex format
     *
     * @return bool
     */
    public function validate(string $token): bool
    {
        //reference to token storage in session
        $tokens = &$_SESSION[static::CSRF_TOKEN_STORAGE];
        //get current size of token storage in session
        $size = \count($tokens);
        //bytes to b16 chars
        $chars = $this->tokenLenght * 2;
        //current time
        $time = \time();

        for ($i = $size -1; $i > -1; $i--) {
            //get token from storage
            //if token in storage doesn't match user token continue
            if (($tmpToken = \substr($tokens[$i], 0, $chars)) !== $token) {
                continue;
            }

            //get time from storage
            $tmpTime = \substr($tokens[$i], $chars);
            //timestamp from token time
            $timestamp = (int) \base_convert($tmpTime, 16, 10);

            //token expiration check
            if (($timestamp + $this->expire) > $time) {
                return true;
            }
        }

        return false;
    }
}
