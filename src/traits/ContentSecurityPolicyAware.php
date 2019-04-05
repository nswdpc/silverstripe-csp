<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;

/**
 * Use this trait to enable the CSP on non ContentController controllers
 * @author James
 */
trait ContentSecurityPolicyAware
{
    public function EnableContentSecurityPolicy()
    {
        return true;
    }
}
