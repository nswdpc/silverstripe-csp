<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Admin\ModelAdmin;

/**
 * Admin for managing Content Security Policy and Violation Reports
 */
class CspModelAdmin extends ModelAdmin
{
    /**
     * @config
     */
    private static string $url_segment = 'content-security-policy';

    /**
     * @config
     */
    private static string $menu_title = 'CSP';

    /**
     * @config
     */
    private static string $menu_icon_class = 'font-icon-block';

    /**
     * @config
     */
    private static array $managed_models = [
        Policy::class,
        Directive::class,
        ViolationReport::class
    ];
}
