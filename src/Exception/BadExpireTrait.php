<?php

/**
 * Linna Cross-site Request Forgery Guard
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\CsrfGuard\Exception;

/**
 * Bad expire trait.
 * Provide a method to check conditions to throw BadExpireException.
 */
trait BadExpireTrait
{
    /**
     * Check bad expire.
     *
     * @param int $expire Expire time in seconds
     *
     * @return void
     *
     * @throws BadExpireException If $expire is less than 0 and greater than 86400
     */
    protected function checkBadExpire(int $expire): void
    {
        // expire maximum time is one day
        if ($expire < 0 || $expire > 86400) {
            throw new BadExpireException('Expire time must be between 0 and 86400');
        }
    }
}
