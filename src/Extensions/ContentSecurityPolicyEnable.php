<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Extension;

/**
 * Apply this to relevant controller types to enable CSP header delivery
 * @author James
 */
class ContentSecurityPolicyEnable extends Extension
{
    public function EnableContentSecurityPolicy()
    {
        return true;
    }
}
