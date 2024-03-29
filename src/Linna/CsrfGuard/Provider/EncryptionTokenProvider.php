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
 * CSRF Encryption based token pattern provider.
 *
 * <p>It use sodium_crypto_aead_xchacha20poly1305_ietf_encrypt fuction to encrypt
 * the token.</p>
 *
 * <p>This token works storing a different key for session and a different nonce for every token in session, store the
 * complete encrypted token isn't stored because the token is valid only if the server is able to decrypt it.</p>
 *
 * <p>An attacker should know the key and the nonce and the time to craft a valid token for the specific session.</p>
 *
 * <p>The space needed is token-length indipendent, 32 bytes for the key and 24 bytes for the nonce. Neet to consider
 * that the key is stored once in session, nonce is stored for every token.</p>
 *
 */
final class EncryptionTokenProvider implements TokenProviderInterface
{
    use BadExpireTrait;
    use BadStorageSizeTrait;
    use BadTokenLengthTrait;
    use SessionNotStartedTrait;

    /** @var string CSRF_ENCRYPTION_KEY Encryption key name in session array. */
    private const CSRF_ENCRYPTION_KEY = 'csrf_encryption_key';

    /** @var string CSRF_ENCRYPTION_NONCE Encryption nonce name in session array. */
    private const CSRF_ENCRYPTION_NONCE = 'csrf_encryption_nonce';

    /**
     * Class constructor.
     *
     * @param int $expire      Token validity in seconds, default 600 -> 10 minutes.
     * @param int $storageSize Maximum token nonces stored for a session.
     * @param int $tokenLength Token length in bytes, the length of the plain text before encryption.
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
        /** @var int $tokenLength Token length in bytes, the length of the plain text before encryption. */
        private int $tokenLength = ExceptionBoundary::TOKEN_LENGTH_MIN
    ) {
        // from BadExpireTrait, BadStorageSizeTrait and SessionNotStartedTrait
        /** @throws BadExpireException */
        $this->checkBadExpire($expire);
        /** @throws BadStorageSizeException */
        $this->checkBadStorageSize($storageSize);
        /** @throws BadTokenLengthException */
        $this->checkBadTokenLength($tokenLength);
        /** @throws SessionNotStartedException */
        $this->checkSessionNotStarted();

        //if no nonce stored, initialize the session storage
        $_SESSION[self::CSRF_ENCRYPTION_NONCE] ??= [];
    }

    /**
     * Return new Encryption based Token.
     *
     * @return string The token in hex format.
     */
    public function getToken(): string
    {
        //get the key for encryption
        $key = $this->getKey();
        //get a new nonce for encryption as result of
        //random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $nonce = $this->getNonce();
        $additionlData = \sodium_bin2hex($nonce);

        //get current time
        $time = \dechex(\time());

        //build message
        $message = \sodium_bin2hex(\random_bytes(\max(ExceptionBoundary::TOKEN_LENGTH_MIN, $this->tokenLength))).$time;

        //create ciphertext
        //https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php
        //https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
        $ciphertext = \sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($message, $additionlData, $nonce, $key);

        return \sodium_bin2hex($ciphertext);
    }

    /**
     * Validate Encryption based Token.
     *
     * @param string $token Token must be validated, hex format.
     *
     * @return bool True if the token is valid, false otherwise.
     */
    public function validate(string $token): bool
    {
        //convert hex token to raw bytes
        $hexToken = \sodium_hex2bin($token);

        // plain text returned from check encryption
        $plainText = '';

        //plainText variable is passed as reference,
        //if checkEncrption method end without errors then checkTime method
        //receive a filled plainText variable as argument else
        //short circuiting make the if block skipped
        if ($this->checkEncryption($hexToken, $plainText) && $this->checkTime($plainText)) {
            return true;
        }

        return false;
    }

    /**
     * Check if token is expired.
     *
     * @param string $token Token after decryption.
     *
     * @return bool True if token isn't expired, false otherwise.
     */
    private function checkTime(string $token): bool
    {
        // get time from token
        $time = \substr($token, $this->tokenLength * 2);

        //timestamp from token time
        $timestamp = \hexdec($time);

        //token expiration check
        if ($timestamp + $this->expire < \time()) {
            return false;
        }

        return true;
    }

    /**
     * Try to decrypt an encrypted token.
     *
     * @param string $encryptedToken Encrypted token.
     * @param string $plainText      Variable passed as reference to store the result.
     *
     * @return bool True in the encrypted token decrypt successfully, false otherwise.
     */
    private function checkEncryption(string $encryptedToken, string &$plainText): bool
    {
        //get the key for encryption
        $key = $this->getKey();
        //reference to nonce storage in session
        $nonces = &$_SESSION[self::CSRF_ENCRYPTION_NONCE];
        //get current size of nonce storage in session
        $size = \count($nonces);

        //try to decrypt starting from last stored nonce
        for ($i = $size -1; $i > -1; $i--) {
            //get nonce
            $nonce = $nonces[$i];
            //generate addition data
            $additionlData = \sodium_bin2hex($nonce);

            //for successful decryption return true
            if (($tmpPlainText = \sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($encryptedToken, $additionlData, $nonce, $key))) {
                //plainText will remain string if sodium_crypto return false
                //todo, check in php source code if sodium_crypto
                //return false if fails
                $plainText = $tmpPlainText;
                //no need to check if the plaintext is the same because if the token is tampered decryption doesn't
                //work
                return true;
            }
        }

        return false;
    }

    /**
     * Return the encryption key for the currente session.
     *
     * <p>Generate a different key for every session.</p>
     *
     * @return string The encryption key.
     */
    private function getKey(): string
    {
        //if key is already stored, return it
        if (isset($_SESSION[self::CSRF_ENCRYPTION_KEY])) {
            return $_SESSION[self::CSRF_ENCRYPTION_KEY];
        }

        //generate new key
        $key = \sodium_crypto_aead_xchacha20poly1305_ietf_keygen();

        //store new key
        $_SESSION[self::CSRF_ENCRYPTION_KEY] = $key;

        return $key;
    }

    /**
     * Generate a new nonce to encrypt the token.
     *
     * @return string The new nonce.
     */
    private function getNonce(): string
    {
        //generate new nonce
        $nonce = \random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        //store new nonce
        $_SESSION[self::CSRF_ENCRYPTION_NONCE][] = $nonce;

        //check if the storage is growt beyond the maximun size
        if (\count($_SESSION[self::CSRF_ENCRYPTION_NONCE]) > $this->storageSize) {
            //remove the oldest stores nonce
            \array_shift($_SESSION[self::CSRF_ENCRYPTION_NONCE]);
        }

        return $nonce;
    }
}
