<?php

declare(strict_types=1);

namespace NSWDPC\Utilities\ContentSecurityPolicy;

/**
 * Use this trait to enable the CSP on non ContentController controllers
 * @author James
 * @phpstan-ignore trait.unused
 */
trait ContentSecurityPolicyAware
{
    public function EnableContentSecurityPolicy(): bool
    {
        return true;
    }
}
