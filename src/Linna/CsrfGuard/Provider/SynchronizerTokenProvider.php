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
use Linna\CsrfGuard\Exception\ExceptionBoundary;
use Linna\CsrfGuard\Exception\SessionNotStartedException;
use Linna\CsrfGuard\Exception\SessionNotStartedTrait;

/**
 * CSRF random (aka Synchronizer) token pattern provider.
 *
 * <p>A random token with the expire time in this type of tokek, the token with the time are stored in session but only
 * the token is returned.</p>
 *
 * <p>
 * The difficulty about guess the token is proportional to his length, the formula is <code>1/16^(token_length*2)</code>.
 * Using a token of 16 byte means <code>1/16^(16*2)</code>, <code>1/16^32</code>.<br/>Who tray to guess the token has
 * a possibility of <code>1/(a number greater than the number of atoms in universe)</code>.
 * </p>
 */
final class SynchronizerTokenProvider implements TokenProviderInterface
{
    use BadExpireTrait;
    use BadStorageSizeTrait;
    use BadTokenLengthTrait;
    use SessionNotStartedTrait;

    /** @var string CSRF_TOKEN_STORAGE Token storage key name in session array. */
    private const CSRF_TOKEN_STORAGE = 'csrf_syncronizer_token';

    /**
     * Class constructor.
     *
     * @param int $expire      Token validity in seconds, default 600 -> 10 minutes.
     * @param int $storageSize Maximum token stored in session.
     * @param int $tokenLength The desidered token length in bytes, token will be the double in chars.
     *
     * @throws BadExpireException         If <code>$expire</code> is less than 0 and greater than 86400.
     * @throws BadStorageSizeException    If <code>$storageSize</code> is less than 2 and greater than 64.
     * @throws BadTokenLengthException    If <code>$tokenLength</code> is less than 16 and greater than 128.
     * @throws SessionNotStartedException If sessions are disabled or no session is started.
     */
    public function __construct(
        /** @var int $expire Token validity in seconds, default 600 -> 10 minutes. */
        private int $expire = 600,
        /** @var int $storageSize Maximum token stored in session. */
        private int $storageSize = 10,
        /** @var int $tokenLength Token length in bytes. */
        private int $tokenLength = 32
    ) {
        // from BadExpireTrait, BadStorageSizeTrait, BadTokenLengthException and SessionNotStartedTrait
        /** @throws BadExpireException */
        $this->checkBadExpire($expire);
        /** @throws BadStorageSizeException */
        $this->checkBadStorageSize($storageSize);
        /** @throws BadTokenLengthException */
        $this->checkBadTokenLength($tokenLength);
        /** @throws SessionNotStartedException */
        $this->checkSessionNotStarted();

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
        $token = \bin2hex(\random_bytes(\max(ExceptionBoundary::TOKEN_LENGTH_MIN, $this->tokenLength)));
        $time = \dechex(\time());

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
            $timestamp = \hexdec($tmpTime);

            //token expiration check
            if (($timestamp + $this->expire) >= $time) {
                return true;
            }

            //remove token expired from session
            unset($tokens[$i]);
        }

        return false;
    }
}
