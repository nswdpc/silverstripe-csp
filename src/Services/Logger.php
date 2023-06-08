<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Security;

/**
 * Simple log handling
 */
class Logger
{
    public static function log($message, $level = "DEBUG")
    {
        Injector::inst()->get(LoggerInterface::class)->log($level, $message);
    }
}
