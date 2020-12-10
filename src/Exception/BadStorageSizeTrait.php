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
     * @throws BadStorageSizeException If $size is less than
     *                                 ExceptionBoundary::STORAGE_SIZE_MIN
     *                                 and greater than
     *                                 ExceptionBoundary::STORAGE_SIZE_MAX
     */
    protected function checkBadStorageSize(int $size): void
    {
        if ($size < ExceptionBoundary::STORAGE_SIZE_MIN || $size > ExceptionBoundary::STORAGE_SIZE_MAX) {
            throw new BadStorageSizeException(
                \sprintf(
                    "Storage size must be between %d and %d)",
                    ExceptionBoundary::STORAGE_SIZE_MIN,
                    ExceptionBoundary::STORAGE_SIZE_MAX
                )
            );
        }
    }
}
