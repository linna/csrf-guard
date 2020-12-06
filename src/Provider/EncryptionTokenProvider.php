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

/**
 * Csrf Encryption Based Token Pattern Provider.
 *
 * It use sodium_crypto_aead_xchacha20poly1305_ietf_encrypt fuction to encrypt
 * the token. Key change every session, nonce change for every token.
 */
class EncryptionTokenProvider implements TokenProviderInterface
{
    /**
     * @var string CSRF_ENCRYPTION_KEY Encryption key name in session array
     */
    private const CSRF_ENCRYPTION_KEY = 'csrf_encryption_key';

    /**
     * @var string CSRF_ENCRYPTION_NONCE Encryption nonce name in session array
     */
    private const CSRF_ENCRYPTION_NONCE = 'csrf_encryption_nonce';

    /**
     * @var string $sessionId Session id of the current session
     */
    private string $sessionId = '';

    /**
     * @var int $sessionIdLen Session id lenght
     */
    private int $sessionIdLen = 0;

    /**
     * @var int $expire Token validity in seconds, default 600 -> 10 minutes
     */
    private int $expire = 0;

    /**
     * @var int $storageSize Maximum token nonces stored in session
     */
    private int $storageSize = 0;

    /**
     * Class constructor.
     *
     * @param string $sessionId   Session id of the current session
     * @param int    $expire      Token validity in seconds, default 600 -> 10 minutes
     * @param int    $storageSize Maximum token nonces stored in session
     *
     * @throws BadExpireException      If $expire is less than 0 and greater than 86400
     * @throws BadStorageSizeException If $storageSize is less than 2 and greater than 64
     */
    public function __construct(string $sessionId, int $expire = 600, int $storageSize = 10)
    {
        // expire maximum tim is one day
        if ($expire < 0 || $expire > 86400) {
            throw new BadExpireException('Expire time must be between 0 and PHP_INT_MAX');
        }

        if ($storageSize < 2 || $storageSize > 64) {
            throw new BadStorageSizeException('Storage size must be between 2 and 64');
        }

        $this->sessionId = $sessionId;
        $this->sessionIdLen = \strlen($sessionId);
        $this->expire = $expire;
        $this->storageSize = $storageSize;

        //if no nonce stored, initialize the session storage
        $_SESSION[static::CSRF_ENCRYPTION_NONCE] ??= [];
    }

    /**
     * Return new Encryption based Token.
     *
     * @return string A hex token
     */
    public function getToken(): string
    {
        //get the key for encryption
        $key = $this->getKey(); //random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        //get a new nonce for encryption
        $nonce = $this->getNonce(); //random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        //get current time
        $time = \base_convert((string) \time(), 10, 16);
        //build message
        $message = $this->sessionId.$time;

        //create ciphertext
        //https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-encrypt.php
        //https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
        $ciphertext = \sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($message, '', $nonce, $key);

        return \sodium_bin2hex($ciphertext);
    }

    /**
     * Validate Encryption based Token.
     *
     * @param string $token Token must be validated, hex format
     *
     * @return bool
     */
    public function validate(string $token): bool
    {
        //convert hex token to raw bytes
        $hex_token = \sodium_hex2bin($token);

        // plain text returned from check encryption
        $plainText = '';

        if ($this->checkEncryption($hex_token, $plainText) && $this->checkTime($plainText)) {
            return true;
        }

        return false;
    }

    /**
     * Check if token is expired.
     *
     * @param string $token Token after decryption
     *
     * @return bool
     */
    private function checkTime(string $token): bool
    {
        $time = \substr($token, $this->sessionIdLen);

        //timestamp from token time
        $timestamp = (int) \base_convert($time, 16, 10);

        //token expiration check
        if ($timestamp + $this->expire < \time()) {
            return false;
        }

        return true;
    }

    /**
     * Try to decrypt a token.
     *
     * @param string $encryptedToken Encrypted token
     * @param string $plainText      Variable passed as reference to store the result
     *
     * @return bool
     */
    private function checkEncryption(string $encryptedToken, string &$plainText): bool
    {
        //get the key for encryption
        $key = $this->getKey();
        //reference to nonce storage in session
        $nonces = &$_SESSION[static::CSRF_ENCRYPTION_NONCE];
        //get current size of nonce storage in session
        $size = \count($nonces);

        //try to decrypt starting from last stored nonce
        for ($i = $size -1; $i > -1; $i--) {
            //for successful decryption return true
            if (($tmpPlainText = \sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($encryptedToken, '', $nonces[$i], $key))) {
                //plainText will remain string
                $plainText = $tmpPlainText;
                return true;
            }
        }

        return false;
    }

    /**
     * Return the encryption key for the currente session.
     * Generate a different key for every session.
     *
     * @return string
     */
    private function getKey(): string
    {
        //if key is already stored, return it
        if (isset($_SESSION[static::CSRF_ENCRYPTION_KEY])) {
            return $_SESSION[static::CSRF_ENCRYPTION_KEY];
        }

        //generate new key
        $key = \random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

        //store new key
        $_SESSION[static::CSRF_ENCRYPTION_KEY] = $key;

        return $key;
    }

    /**
     * Generate a new nonce for encrypt the token.
     *
     * @return string
     */
    private function getNonce(): string
    {
        //generate new nonce
        $nonce = \random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        //store new nonce
        $_SESSION[static::CSRF_ENCRYPTION_NONCE][] = $nonce;

        //check if the storage is growt beyond the maximun size
        if (\count($_SESSION[static::CSRF_ENCRYPTION_NONCE]) > $this->storageSize) {
            //remove the oldest stores nonce
            \array_shift($_SESSION[static::CSRF_ENCRYPTION_NONCE]);
        }

        return $nonce;
    }
}
