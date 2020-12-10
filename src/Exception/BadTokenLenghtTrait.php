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
 * Bad token lenght trait.
 * Provide a method to check conditions to throw BadTokenLenghtException.
 */
trait BadTokenLenghtTrait
{
    /**
     * Check bad token lenght.
     *
     * @param int $tokenLenght Token lenght in bytes
     *
     * @return void
     *
     * @throws BadTokenLenghtException If $tokenLenght is less than
     *                                 ExceptionBoundary::TOKEN_LENGHT_MIN
     *                                 and greater than
     *                                 ExceptionBoundary::TOKEN_LENGHT_MAX
     */
    protected function checkBadTokenLenght(int $tokenLenght): void
    {
        if ($tokenLenght < ExceptionBoundary::TOKEN_LENGHT_MIN || $tokenLenght > ExceptionBoundary::TOKEN_LENGHT_MAX) {
            throw new BadTokenLenghtException(
                \sprintf(
                    "Token lenght must be between %d and %d",
                    ExceptionBoundary::TOKEN_LENGHT_MIN,
                    ExceptionBoundary::TOKEN_LENGHT_MAX
                )
            );
        }
    }
}
