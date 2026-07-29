<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;
use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Dev\TestOnly;

class TestPage extends SiteTree implements TestOnly
{

    public function getControllerName()
    {
        return TestPageController::class;
    }

}
