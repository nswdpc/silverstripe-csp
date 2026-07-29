<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;
use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\Dev\TestOnly;
use SilverStripe\View\Requirements;

class TestPageController extends ContentController implements TestOnly
{

    public function doInit() {
        parent::doInit();
        $this->addRequirements();
    }

    protected function addRequirements()
    {
        Requirements::javascript(
            "https://example.com/example.js",
            // This script can have these custom attributes but no nonce
            [
                "async" => true,
                "defer" => true,
                "data-example-1" => "test1",
                'integrity' => 'some-script-hash',
                'crossorigin' => 'anonymous'
            ]
        );

        // Custom script should get the nonce attribute
        Requirements::customScript(
            "console.log('testCustomScript1');",
            "testCustomScript1"
        );

        // Custom script should get the nonce attribute and retain custom attributes
        Requirements::customScriptWithAttributes(
            "console.log('testCustomScriptWithAttributes');",
            [
                "data-example-2" => "test2",
                "defer" => true,
                "async" => true
            ],
            "testCustomScriptWithAttributes"
        );

        // This CSS included via link tag will get no nonce but retain custom attributes
        Requirements::css(
            "https://example.com/example.css",
            "screen",
            [
                "data-example-3" => "test3",
                'integrity' => 'some-style-hash',
                'crossorigin' => 'anonymous'
            ]
        );

        // This custom CSS should get a nonce attribute and a type attribute
        Requirements::customCSS(
            "div { outline: red; }",
            "testCustomStyle1"
        );
    }
}
