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
     * @throws BadTokenLenghtException If $tokenLenght is less than 16 and greater than 128
     */
    protected function checkBadTokenLenght(int $tokenLenght): void
    {
        if ($tokenLenght < 16 || $tokenLenght > 128) {
            throw new BadTokenLenghtException('Token lenght must be between 16 and 128');
        }
    }
}
