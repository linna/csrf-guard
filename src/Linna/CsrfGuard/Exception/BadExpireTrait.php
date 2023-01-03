<?php

declare(strict_types=1);

/**
 * This file is part of the Linna Csrf Guard.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */

namespace Linna\CsrfGuard\Exception;

/**
 * Bad expire trait.
 * 
 * <p>Provide a method to check conditions to throw BadExpireException.</p>
 */
trait BadExpireTrait
{
    /**
     * Check for a wrog expire time for a token.
     *
     * @param int $expire Expire time in seconds.
     *
     * @return void
     *
     * @throws BadExpireException If $expire is less than <code>ExceptionBoundary::EXPIRE_MIN</code> and greater than
     *                            <code>ExceptionBoundary::EXPIRE_MAX</code>.
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
