<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Policy;

require_once(dirname(__FILE__) . '/AbstractPolicyFunctionalTest.php');

/**
 * Functional test using Middleware as the nonce injection solution
 */
class MiddlewarePolicyFunctionalTest extends AbstractPolicyFunctionalTest
{

    protected function getInjectionMethod() {
        return Policy::NONCE_INJECT_VIA_MIDDLEWARE;
    }

}
