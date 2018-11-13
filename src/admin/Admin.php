<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use SilverStripe\Admin\ModelAdmin;

/**
 * Admin for managing Content Security Policy and Violation Reports
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspModelAdmin extends ModelAdmin {
  private static $url_segment = 'content-security-policy';
  private static $menu_title = 'CSP';
  /**
   * Menu icon for Left and Main CMS
   * @var string
   */
  private static $menu_icon = '/framework/admin/images/menu-icons/16x16/gears.png';
  private static $managed_models = [
    Policy::class,
    ViolationReport::class
  ];

}
