<?php

declare(strict_types=1);

/**
 * This file is part of the Linna Csrf Guard.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */

namespace Linna\CsrfGuard\Provider;

use Linna\CsrfGuard\Exception\BadExpireException;
use Linna\CsrfGuard\Exception\BadStorageSizeException;
use Linna\CsrfGuard\Exception\BadTokenLengthException;
use Linna\CsrfGuard\Exception\BadExpireTrait;
use Linna\CsrfGuard\Exception\BadStorageSizeTrait;
use Linna\CsrfGuard\Exception\BadTokenLengthTrait;
use Linna\CsrfGuard\Exception\SessionNotStartedException;
use Linna\CsrfGuard\Exception\SessionNotStartedTrait;

/**
 * Syncronizer token provider.
 *
 * <p>A random token with the expire time.</p>
 */
class SynchronizerTokenProvider implements TokenProviderInterface
{
    use BadExpireTrait;
    use BadStorageSizeTrait;
    use BadTokenLengthTrait;
    use SessionNotStartedTrait;

    /** @var string CSRF_TOKEN_STORAGE Token storage key name in session array. */
    private const CSRF_TOKEN_STORAGE = 'csrf_syncronizer_token';

    /** @var int $expire Token validity in seconds, default 600 -> 10 minutes. */
    private int $expire = 0;

    /** @var int $tokenLength Token length in chars. */
    private int $tokenLength = 32;

    /** @var int $storageSize Maximum token nonces stored in session. */
    private int $storageSize = 10;

    /**
     * Class constructor.
     *
     * @param int $expire      Token validity in seconds, default 600 -> 10 minutes.
     * @param int $storageSize Maximum token nonces stored in session.
     * @param int $tokenLength The desidered token length in bytes, consider that the time is added to the token.
     *
     * @throws BadExpireException      If <code>$expire</code> is less than 0 and greater than 86400.
     * @throws BadStorageSizeException If <code>$storageSize</code> is less than 2 and greater than 64.
     * @throws BadTokenLengthException If <code>$tokenLength</code> is less than 16 and greater than 128.
     */
    public function __construct(int $expire = 600, int $storageSize = 10, int $tokenLength = 32)
    {
        // from BadExpireTrait, BadStorageSizeTrait, BadTokenLengthException and SessionNotStartedTrait
        /** @throws BadExpireException */
        $this->checkBadExpire($expire);
        /** @throws BadStorageSizeException */
        $this->checkBadStorageSize($storageSize);
        /** @throws BadTokenLengthException */
        $this->checkBadTokenLength($tokenLength);
        /** @throws SessionNotStartedException */
        $this->checkSessionNotStarted();

        $this->expire = $expire;
        $this->tokenLength = $tokenLength;
        $this->storageSize = $storageSize;

        //if any token stored, initialize the session storage
        $_SESSION[self::CSRF_TOKEN_STORAGE] ??= [];
    }

    /**
     * Return new Synchronizer based Token.
     *
     * @return string The token in hex format.
     */
    public function getToken(): string
    {
        //generate new token
        $token = \bin2hex(\random_bytes(\max(1, $this->tokenLength)));
        $time = \base_convert((string) \time(), 10, 16);

        //store new token
        $_SESSION[self::CSRF_TOKEN_STORAGE][] = $token.$time;

        //check if the storage is growt beyond the maximun size
        if (\count($_SESSION[self::CSRF_TOKEN_STORAGE]) > $this->storageSize) {
            //remove the oldest stores nonce
            \array_shift($_SESSION[self::CSRF_TOKEN_STORAGE]);
        }

        return $token;
    }

    /**
     * Validate Synchronizer based Token.
     *
     * @param string $token Token must be validated, hex format.
     *
     * @return bool True if the token is valid, false otherwise.
     */
    public function validate(string $token): bool
    {
        //reference to token storage in session
        $tokens = &$_SESSION[self::CSRF_TOKEN_STORAGE];
        //get current size of token storage in session
        $size = \count($tokens);
        //bytes to b16 chars
        $chars = $this->tokenLength * 2;
        //current time
        $time = \time();

        for ($i = $size -1; $i > -1; $i--) {
            //get token from storage
            //if token in storage doesn't match user token continue
            if (($tmpToken = \substr($tokens[$i], 0, $chars)) !== $token) {
                continue;
            }

            //get time from storage
            //subtract the length of the token to the token+time
            $tmpTime = \substr($tokens[$i], $chars);
            //timestamp from token time
            $timestamp = (int) \base_convert($tmpTime, 16, 10);

            //token expiration check
            if (($timestamp + $this->expire) > $time) {
                return true;
            }

            //remove token expired from session
            unset($tokens[$i]);
        }

        return false;
    }
}
