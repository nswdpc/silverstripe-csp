<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Forms\FieldList;

/**
 * The Nothing class does nothing and exists only to test CI workflow
 */
class Nothing {

    const TEST = "test";

    private static $something = 'Nothing Really';


    private static $check = [
        'Foo' => 'Bar'
    ];


    public function doNothing(string $params = '') {
        $fields = [
            'foo' => 'bar'
        ];
        $foo = 'bar';
        return $fields;
    }

    protected static function doNothing2(array $data): bool {
        $fields = [
            'foo' => 'bar',
                'indent' => 'more'
        ];
        if(true == true) {
            return true;
        } else {
            return false;
        }
    }

}
