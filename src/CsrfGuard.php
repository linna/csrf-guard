<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna;

use RuntimeException;
use InvalidArgumentException;

/**
 * Cross-site Request Forgery Guard
 */
class CsrfGuard
{
    /**
     * @var string Token storage key name in session array.
     */
    public const TOKEN_STORAGE = 'csrf-tokens';

    /**
     * @var array<mixed> Reference to php session data from superglobal.
     */
    private array $storage;

    /**
     * @var int Max number of tokens stored in session.
     */
    private int $maxStorage;

    /**
     * @var int Rapresent the lenght of the token in bytes.
     */
    private int $tokenStrength;

    /**
     * Class constructor.
     *
     * @param int $maxStorage    Max number of tokens stored in session, work as
     *                           FIFO data structure, when maximun capacity is
     *                           reached, oldest token be dequeued from storage.
     * @param int $tokenStrength Rapresent the lenght of the token in bytes.
     *
     * @throws RuntimeException  If instance is created without start session
     *                           before and if token strenght parameter is
     *                           less than 16.
     */
    public function __construct(int $maxStorage, int $tokenStrength = 16)
    {
        //check if session is started
        if (\session_status() === PHP_SESSION_NONE) {
            throw new RuntimeException('Session must be started before create instance.');
        }

        //check for minimun token strenth
        if ($tokenStrength < 16) {
            throw new RuntimeException('The minimum CSRF token strength is 16.');
        }

        //initialize session storage
        $_SESSION[self::TOKEN_STORAGE] = $_SESSION[self::TOKEN_STORAGE] ?? [];

        $this->storage = &$_SESSION[self::TOKEN_STORAGE];
        $this->maxStorage = $maxStorage;
        $this->tokenStrength = $tokenStrength;
    }

    /**
     * Limit number of token stored in session.
     *
     * @param array<mixed> $array
     */
    private function dequeue(array &$array): void
    {
        if (\count($array) > $this->maxStorage) {
            \array_shift($array);
        }
    }

    /**
     * Return csrf token as array.
     *
     * @return array<mixed>
     */
    public function getToken(): array
    {
        //generate new token
        $token = $this->generateToken();
        //pick the name of the token
        $name = $token['name'];
        //store the token
        $this->storage[$name] = $token;

        //storage cleaning!
        //warning!! if you get in a page more token of maximun storage,
        //will there a leak of token, the firsts generated
        //in future I think throw and exception.
        $this->dequeue($this->storage);

        return $token;
    }

    /**
     * Return timed csrf token as array.
     *
     * @param int $ttl Time to live for the token, default 600 -> 10 minutes.
     *
     * @return array<mixed>
     */
    public function getTimedToken(int $ttl = 600): array
    {
        //generate new token
        $token = $this->generateToken();
        //store token expiration
        //add new key to token array
        $token['time'] = \time() + $ttl;
        //pick the name of the token
        $name = $token['name'];
        //store the token
        $this->storage[$name] = $token;

        //storage cleaning
        $this->dequeue($this->storage);

        return $token;
    }

    /**
     * Generate a random token.
     *
     * @return array<mixed>
     */
    private function generateToken(): array
    {
        //generate a random token name
        $name = 'csrf_'.\bin2hex(\random_bytes(8));
        //generate a random token value
        $value = \bin2hex(\random_bytes($this->tokenStrength));

        return ['name' => $name, 'value' => $value];
    }

    /**
     * Validate a csrf token or a csrf timed token.
     *
     * @param array<mixed> $requestData From request or from superglobal variables $_POST,
     *                                  $_GET, $_REQUEST and $_COOKIE.
     *
     * @return bool
     */
    public function validate(array $requestData): bool
    {
        //apply matchToken method elements of passed data,
        //using this instead of forach for code shortness.
        $array = \array_filter($requestData, array($this, 'doChecks'), ARRAY_FILTER_USE_BOTH);

        return (bool) \count($array);
    }

    /**
     * Tests for valid token.
     *
     * @param string $value
     * @param string $key
     *
     * @return bool
     */
    private function doChecks(string $value, string $key): bool
    {
        return $this->tokenIsValid($value, $key) &&
               $this->tokenIsExpired($key)  &&
               $this->deleteToken($key);
    }

    /**
     * Delete token after validation.
     *
     * @param string $key
     *
     * @return bool
     */
    private function deleteToken(string &$key): bool
    {
        unset($this->storage[$key]);

        return true;
    }

    /**
     * Check if token is valid
     *
     * @param string $value
     * @param string $key
     *
     * @return bool
     */
    private function tokenIsValid(string &$value, string &$key): bool
    {
        //if token doesn't exist
        if (empty($this->storage[$key])) {
            return false;
        }

        return \hash_equals($this->storage[$key]['value'], $value);
    }

    /**
     * Check if timed token is expired.
     *
     * @param string $key
     *
     * @return bool
     */
    private function tokenIsExpired(string &$key): bool
    {
        //if timed and if time is valid
        if (isset($this->storage[$key]['time']) && $this->storage[$key]['time'] < \time()) {
            return false;
        }

        return true;
    }

    /**
     * Clean CSRF storage when full.
     *
     * @param int $preserve Token that will be preserved.
     */
    public function garbageCollector(int $preserve): void
    {
        if ($this->maxStorage === \count($this->storage)) {
            $this->cleanStorage($preserve);
        }
    }

    /**
     * Clean CSRF storage.
     *
     * @param int $preserve Token that will be preserved.
     */
    public function clean(int $preserve): void
    {
        $this->cleanStorage($preserve);
    }

    /**
     * Do the CSRF storage cleand.
     *
     * @param int $preserve Token that will be preserved.
     *
     * @throws InvalidArgumentException If arguments lesser than 0 or grater than max storage value.
     */
    private function cleanStorage(int $preserve = 0): void
    {
        if ($preserve < 0) {
            throw new InvalidArgumentException('Argument value should be grater than zero.');
        }

        if ($preserve > $this->maxStorage) {
            throw new InvalidArgumentException("Argument value should be lesser than max storage value ({$this->maxStorage}).");
        }

        $this->storage = \array_splice($this->storage, -$preserve);
    }
}
