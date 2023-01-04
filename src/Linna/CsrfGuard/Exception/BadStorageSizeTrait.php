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
 * Bad storage size trait.
 *
 * <p>Provide a method to check conditions to throw BadStorageSizeException.</p>
 */
trait BadStorageSizeTrait
{
    /**
     * Check for a wrong storage size.
     *
     * @param int $size Size expressed in number of tokens will be stored.
     *
     * @return void
     *
     * @throws BadStorageSizeException If $size is less than <code>ExceptionBoundary::STORAGE_SIZE_MIN</code> and
     *                                 greater than <code>ExceptionBoundary::STORAGE_SIZE_MAX</code>.
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
