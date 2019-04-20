<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@alice.it>
 * @copyright (c) 2018, Sebastian Rapetti
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
     * @var array Php session data from superglobal.
     */
    private $session;

    /**
     * @var int Max number of tokens stored in session.
     */
    private $maxStorage;

    /**
     * @var int Rapresent the lenght of the token in bytes.
     */
    private $tokenStrength;

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
     *                           less than 16
     */
    public function __construct(int $maxStorage, int $tokenStrength = 16)
    {
        if (\session_status() === 1) {
            throw new RuntimeException('Session must be started before create instance.');
        }

        if ($tokenStrength < 16) {
            throw new RuntimeException('The minimum CSRF token strength is 16.');
        }

        $_SESSION['CSRF'] = $_SESSION['CSRF'] ?? [];

        $this->session = &$_SESSION;
        $this->maxStorage = $maxStorage;
        $this->tokenStrength = $tokenStrength;
    }

    /**
     * Limit number of token stored in session.
     *
     * @param array $array
     */
    private function dequeue(array &$array): void
    {
        $size = \count($array);

        while ($size > $this->maxStorage) {
            \array_shift($array);
            $size--;
        }
    }

    /**
     * Return csrf token as array.
     *
     * @return array
     */
    public function getToken(): array
    {
        $token = $this->generateToken();

        $name = $token['name'];

        $this->session['CSRF'][$name] = $token;

        //storage cleaning!
        //warning!! if you get in a page more token of maximun storage,
        //will there a leak of token, the firsts generated
        //in future I think throw and exception.
        $this->dequeue($this->session['CSRF']);

        return $token;
    }

    /**
     * Return timed csrf token as array.
     *
     * @param int $ttl Time to live for the token.
     *
     * @return array
     */
    public function getTimedToken(int $ttl): array
    {
        $token = $this->generateToken();
        $token['time'] = \time() + $ttl;

        $name = $token['name'];

        $this->session['CSRF'][$name] = $token;

        $this->dequeue($this->session['CSRF']);

        return $token;
    }

    /**
     * Generate a random token.
     *
     * @return array
     */
    private function generateToken(): array
    {
        $name = 'csrf_'.\bin2hex(\random_bytes(8));
        $value = \bin2hex(\random_bytes($this->tokenStrength));

        return ['name' => $name, 'value' => $value];
    }

    /**
     * Validate a csrf token or a csrf timed token.
     *
     * @param array $requestData From request or from superglobal variables $_POST,
     *                           $_GET, $_REQUEST and $_COOKIE.
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
        $tokens = &$this->session['CSRF'];

        return $this->tokenIsValid($tokens, $value, $key) &&
               $this->tokenIsExiperd($tokens, $key)  &&
               $this->deleteToken($tokens, $key);
    }

    /**
     * Delete token after validation.
     *
     * @param array  $tokens
     * @param string $key
     *
     * @return bool
     */
    private function deleteToken(array &$tokens, string &$key): bool
    {
        unset($tokens[$key]);

        return true;
    }

    /**
     * Check if token is valid
     *
     * @param array  $tokens
     * @param string $value
     * @param string $key
     *
     * @return bool
     */
    private function tokenIsValid(array &$tokens, string &$value, string &$key): bool
    {
        //if token is not existed
        if (empty($tokens[$key])) {
            return false;
        }

        //if the hash of token and value are not equal
        if (!\hash_equals($tokens[$key]['value'], $value)) {
            return false;
        }

        return true;
    }

    /**
     * Check if timed token is expired.
     *
     * @param array  $tokens
     * @param string $key
     *
     * @return bool
     */
    private function tokenIsExiperd(array &$tokens, string &$key): bool
    {
        //if timed and if time is valid
        if (isset($tokens[$key]['time']) && $tokens[$key]['time'] < \time()) {
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
        if ($this->maxStorage === \count($this->session['CSRF'])) {
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
    private function cleanStorage(int $preserve): void
    {
        if ($preserve < 0) {
            throw new InvalidArgumentException('Argument value should be grater than zero.');
        }

        if ($preserve > $this->maxStorage) {
            throw new InvalidArgumentException("Argument value should be lesser than max storage value ({$this->maxStorage}).");
        }

        $tokens = &$this->session['CSRF'];
        $tokens = \array_splice($tokens, -$preserve);
    }
}
