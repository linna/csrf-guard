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

/**
 * Token provider interface.
 * Define which method should implement a token provider.
 */
interface TokenProviderInterface
{
    /**
     * Return a fresh generated csrf token.
     *
     * @return string
     */
    public function getToken(): string;

    /**
     * Validate a previous generated token.
     *
     * @param string $token
     *
     * @return bool
     */
    public function validate(string $token): bool;
}
