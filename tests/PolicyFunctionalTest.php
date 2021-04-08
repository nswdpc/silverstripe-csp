<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy\Tests;

use NSWDPC\Utilities\ContentSecurityPolicy\Policy;

/**
 * Functional test using Requirements)_Backend as the nonce injection solution
 */
class PolicyFunctionalTest extends AbstractPolicyFunctionalTest
{

    protected function getInjectionMethod() {
        return Policy::NONCE_INJECT_VIA_REQUIREMENTS;
    }

}
