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

/**
 * Token provider interface.
 *
 * <p>Define which method should implement a token provider.</p>
 */
interface TokenProviderInterface
{
    /**
     * Return a fresh generated csrf token.
     *
     * @return string The CSRF token.
     */
    public function getToken(): string;

    /**
     * Validate a previous generated token.
     *
     * @param string $token The CSRF token to validate.
     *
     * @return bool True if the token is valid, false otherwise.
     */
    public function validate(string $token): bool;
}
