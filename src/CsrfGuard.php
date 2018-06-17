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
     */
    public function __construct(int $maxStorage, int $tokenStrength)
    {
        if (session_status() === 1) {
            throw new RuntimeException(__CLASS__.': Session must be started before create '.__CLASS__.' instance.');
        }

        //if csrf array doesn't exist inside session, initialize it.
        //for code shortness: Null coalescing operator
        //http://php.net/manual/en/migration70.new-features.php
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
        $size = count($array);

        while ($size > $this->maxStorage) {
            array_shift($array);
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
        $token['time'] = time() + $ttl;

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
        $name = 'csrf_'.bin2hex(random_bytes(8));
        $value = bin2hex(random_bytes($this->tokenStrength));

        return ['name' => $name, 'value' => $value];
    }

    /**
     * Return csrf token as hidden input form.
     *
     * @return string
     *
     * @deprecated since version 1.1.0
     */
    public function getHiddenInput(): string
    {
        $token = $this->getToken();

        return '<input type="hidden" name="'.$token['name'].'" value="'.$token['value'].'" />';
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
        $array = array_filter($requestData, array($this, 'doChecks'), ARRAY_FILTER_USE_BOTH);

        return (bool) count($array);
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
     * @param array $tokens
     * @param string $key
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
     * @param array $tokens
     * @param string $value
     * @param string $key
     *
     * @return bool
     */
    private function tokenIsValid(array &$tokens, string &$value, string &$key): bool
    {
        //if token exist
        if (!isset($tokens[$key])) {
            return false;
        }

        //if token has valid value
        if (!hash_equals($tokens[$key]['value'], $value)) {
            return false;
        }

        return true;
    }

    /**
     * Check if timed token is expired.
     *
     * @param array $tokens
     * @param string $key
     *
     * @return bool
     */
    private function tokenIsExiperd(array &$tokens, string &$key): bool
    {
        //if timed and if time is valid
        if (isset($tokens[$key]['time']) && $tokens[$key]['time'] < time()) {
            return false;
        }

        return true;
    }
}
