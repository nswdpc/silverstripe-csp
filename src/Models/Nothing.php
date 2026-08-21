<?php

declare(strict_types=1);

namespace NSWDPC\Utilities\ContentSecurityPolicy;

/**
 * The Nothing class does nothing and exists only to test CI workflow
 */
class Nothing
{
    public const TEST = "test";

    private static string $something = 'Nothing Really';


    private static array $check = [
        'Foo' => 'Bar'
    ];


    public function doNothing(string $params = ''): array
    {
        return [
            'foo' => 'bar'
        ];
    }

    protected static function doNothing2(array $data): bool
    {
        return true === true;
    }

}
