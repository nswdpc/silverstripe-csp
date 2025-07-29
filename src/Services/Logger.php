<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Injector\Injector;

/**
 * Simple log handling
 */
class Logger
{
    public static function log(string|\Stringable $message, $level = "DEBUG")
    {
        Injector::inst()->get(LoggerInterface::class)->log($level, $message);
    }
}
