<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Policy;

require_once(__DIR__ . '/DefaultPolicyFunctionalTestcase.php');

/**
 * Functional test using Requirements_Backend as the nonce injection solution
 */
class PolicyFunctionalTest extends DefaultPolicyFunctionalTestcase
{
    protected function getInjectionMethod(): string
    {
        return Policy::NONCE_INJECT_VIA_REQUIREMENTS;
    }

}
