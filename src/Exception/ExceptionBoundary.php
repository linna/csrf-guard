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
 * Excepiton Boundary
 * This class contains constants about expetions limits.
 * Will be replaced with enum type when php will support it.
 */
class ExceptionBoundary
{
    public const EXPIRE_MIN = 0;
    public const EXPIRE_MAX = 86400;

    public const STORAGE_SIZE_MIN = 2;
    public const STORAGE_SIZE_MAX = 64;

    public const TOKEN_LENGHT_MIN = 16;
    public const TOKEN_LENGHT_MAX = 128;

    /**
     * Class constructor.
     * Private because this class must no have instances.
     * Private make impossible to create instance with the new keyword.
     */
    private function __construct()
    {
    }
}
