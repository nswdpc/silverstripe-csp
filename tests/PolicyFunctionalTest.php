<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Policy;

require_once(dirname(__FILE__) . '/AbstractPolicyFunctionalTest.php');

/**
 * Functional test using Requirements_Backend as the nonce injection solution
 */
class PolicyFunctionalTest extends AbstractPolicyFunctionalTest
{

    protected function getInjectionMethod() {
        return Policy::NONCE_INJECT_VIA_REQUIREMENTS;
    }

}
