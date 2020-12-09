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
 * Bad storage size trait.
 * Provide a method to check conditions to throw BadStorageSizeException.
 */
trait BadStorageSizeTrait
{
    /**
     * Check bad storage size.
     *
     * @param int $size Size expressed in number of tokens
     *
     * @return void
     *
     * @throws BadStorageSizeException If $size is less than 2 and greater than 64
     */
    protected function checkBadStorageSize(int $size): void
    {
        if ($size < 2 || $size > 64) {
            throw new BadStorageSizeException('Storage size must be between 2 and 64');
        }
    }
}
