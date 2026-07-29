<?php

declare(strict_types=1);

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Extension;

/**
 * Apply this to relevant controller types to enable CSP header delivery
 * @author James
 * @extends \SilverStripe\Core\Extension<(\SilverStripe\Security\Security & static)>
 */
class ContentSecurityPolicyEnable extends Extension
{
    public function EnableContentSecurityPolicy(): bool
    {
        return true;
    }
}
