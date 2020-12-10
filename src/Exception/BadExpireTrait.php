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
     * @throws BadExpireException If $expire is less than
     *                            ExceptionBoundary::EXPIRE_MIN
     *                            and greater than
     *                            ExceptionBoundary::EXPIRE_MAX
     */
    protected function checkBadExpire(int $expire): void
    {
        if ($expire < ExceptionBoundary::EXPIRE_MIN || $expire > ExceptionBoundary::EXPIRE_MAX) {
            throw new BadExpireException(
                \sprintf(
                    "Expire time must be between %d and %d)",
                    ExceptionBoundary::EXPIRE_MIN,
                    ExceptionBoundary::EXPIRE_MAX
                )
            );
        }
    }
}
