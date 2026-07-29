<?php

declare(strict_types=1);

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Dev\TestOnly;

class TestPage extends SiteTree implements TestOnly
{
    #[\Override]
    public function getControllerName()
    {
        return TestPageController::class;
    }

}
