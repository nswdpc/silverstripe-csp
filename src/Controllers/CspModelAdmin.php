<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Admin\ModelAdmin;

/**
 * Admin for managing Content Security Policy and Violation Reports
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspModelAdmin extends ModelAdmin
{
    private static $url_segment = 'content-security-policy';
    private static $menu_title = 'CSP';
    private static $menu_icon_class = 'font-icon-block';
    private static $managed_models = [
        Policy::class,
        Directive::class,
        ViolationReport::class
    ];
}
