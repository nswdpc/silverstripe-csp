<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Admin\ModelAdmin;

/**
 * Admin for managing Content Security Policy and Violation Reports
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspModelAdmin extends ModelAdmin
{
    /**
     * @var string
     * @config
     */
    private static $url_segment = 'content-security-policy';

    /**
     * @var string
     * @config
     */
    private static $menu_title = 'CSP';

    /**
     * @var string
     * @config
     */
    private static $menu_icon_class = 'font-icon-block';

    /**
     * @var array
     * @config
     */
    private static $managed_models = [
        Policy::class,
        Directive::class,
        ViolationReport::class
    ];
}
