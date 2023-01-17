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
 * Excepiton Boundary.
 *
 * <p>This class contains constants about expetions limits.</p>
 * <p>Will be replaced with enum type when php will support it.</p>
 */
class ExceptionBoundary
{
    public const EXPIRE_MIN = 0;
    public const EXPIRE_MAX = 86400;

    public const STORAGE_SIZE_MIN = 2;
    public const STORAGE_SIZE_MAX = 64;

    public const TOKEN_LENGTH_MIN = 16;
    public const TOKEN_LENGTH_MAX = 128;

    /**
     * Class constructor.
     * <p>Private because this class must no have instances.</p>
     * <p>Private make impossible to create instance with the new keyword.</p>
     */
    private function __construct()
    {
    }
}
