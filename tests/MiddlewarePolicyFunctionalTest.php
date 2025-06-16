<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Policy;

require_once(__DIR__ . '/AbstractPolicyFunctionalTest.php');

/**
 * Functional test using Middleware as the nonce injection solution
 */
class MiddlewarePolicyFunctionalTest extends AbstractPolicyFunctionalTest
{
    protected function getInjectionMethod(): string
    {
        return Policy::NONCE_INJECT_VIA_MIDDLEWARE;
    }

}
