<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@alice.it>
 * @copyright (c) 2017, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna;

/**
 * Cross-site Request Forgery Guard
 */
class CsrfGuard
{
    /**
     * @var Session The session class.
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
     * Constructor.
     *
     * @param int $maxStorage    Max number of tokens stored in session, work as
     *                           FIFO data structure, when maximun capacity is
     *                           reached, oldest token be dequeued from storage.
     * @param int $tokenStrength Rapresent the lenght of the token in bytes.
     */
    public function __construct(int $maxStorage, int $tokenStrength)
    {
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
     */
    private function dequeue(array &$array)
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
    public function getToken() : array
    {
        $tokenName = 'csrf_'.bin2hex(random_bytes(8));
        $token = bin2hex(random_bytes($this->tokenStrength));

        $this->session['CSRF'][$tokenName] = $token;

        //storage cleaning!
        //warning!! if you get in a page more token of maximun storage,
        //will there a leak of token, the firsts generated
        //in future I think throw and exception.
        $this->dequeue($this->session['CSRF']);
        
        return ['name' => $tokenName, 'token' => $token];
    }

    /**
     * Return csrf token as hidden input form.
     *
     * @return string
     */
    public function getHiddenInput() : string
    {
        $token = $this->getToken();

        return '<input type="hidden" name="'.$token['name'].'" value="'.$token['token'].'" />';
    }

    /**
     * Validate a csrf token.
     *
     * @param array $requestData From request or from superglobal variables $_POST,
     *                           $_GET, $_REQUEST and $_COOKIE.
     *
     * @return bool
     */
    public function validate(array $requestData) : bool
    {
        $arrayToken = $this->session['CSRF'];

        foreach ($requestData as $key => $value) {
            if (isset($arrayToken[$key]) && hash_equals($arrayToken[$key], $value)) {
                return true;
            }
        }

        return false;
    }
}
