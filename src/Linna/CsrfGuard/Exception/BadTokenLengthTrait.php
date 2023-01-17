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
 * Bad token length trait.
 *
 * <p>Provide a method to check conditions to throw BadTokenLengthException.</p>
 */
trait BadTokenLengthTrait
{
    /**
     * Check for a wrong token length.
     *
     * @param int $tokenLength Token length in bytes.
     *
     * @return void
     *
     * @throws BadTokenLengthException If $tokenLength is less than <code>ExceptionBoundary::TOKEN_LENGTH_MIN</code>
     *                                 and greater than <code>ExceptionBoundary::TOKEN_LENGTH_MAX</code>.
     */
    final protected function checkBadTokenLength(int $tokenLength): void
    {
        if ($tokenLength < ExceptionBoundary::TOKEN_LENGTH_MIN || $tokenLength > ExceptionBoundary::TOKEN_LENGTH_MAX) {
            throw new BadTokenLengthException(
                \sprintf(
                    "Token length must be between %d and %d",
                    ExceptionBoundary::TOKEN_LENGTH_MIN,
                    ExceptionBoundary::TOKEN_LENGTH_MAX
                )
            );
        }
    }
}
