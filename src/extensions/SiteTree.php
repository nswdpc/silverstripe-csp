<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use CspPolicy;
use Extension;
use Versioned;
use Controller;
use Config;
use DropdownField;
use FieldList;
use HTMLText;
use DBField;
use SiteTree;

/**
 * Provides an extension method so that the SiteTree can gather the CSP meta tag if that is set
 * @author james.ellis@dpc.nsw.gov.au
 */
class SiteTreeExtension extends Extension {

  /**
   * Has_one relationship
   * @var array
   */
  private static $has_one = [
      'CspPolicy' => CspPolicy::class, // a page can have a CSP
  ];

  /**
   * Update Fields
   * @return FieldList
   */
  public function updateSettingsFields(FieldList $fields)
  {
      $fields->addFieldToTab(
          'Root.CSP',
          DropdownField::create(
              'CspPolicyID',
              'Content Security Policy',
              CspPolicy::get()->sort('Title ASC')->filter('Enabled', 1)->exclude('IsBasePolicy', 1)->map('ID', 'Title')
          )->setEmptyString('')
              ->setDescription(_t('ContentSecurityPolicy.ADDITION_SECURITY_POLICY', 'Choose an additional Content Security Policy to apply on this page only.<br>Adding additional policies can only further restrict the capabilities of the protected resource.'))
      );
      return $fields;
  }

  /**
   * Check to see if a meta tag can be returned
   */
  private function checkCanRun() {
    $whitelisted_controllers = Config::inst()->get( CspPolicy::class, 'whitelisted_controllers');
    $controller = Controller::curr();
    if(!$controller) {
        // no current controller
        return false;
    }

    if( is_array($whitelisted_controllers) && in_array(get_class($controller), $whitelisted_controllers) ) {
      //SS_Log::log( "Not running in whitelisted controller:" . get_class($this->owner), SS_Log::DEBUG);
      return false;
    }

    return true;
  }

   /**
    * Extension hook, see {@link SiteTree::MetaTags}
    * @returns void
    */
   public function MetaTags(&$tags) {
       $csp_tags = $this->CspMetaTags();
       $tags = $tags . "\n" . $csp_tags;
   }

  /**
   * Note that reporting is ignored/disallowed when using a meta tag. Only the header Content-Security-Policy is allowed.
   * In your template this can be called directly by adding $CspMetaTags if you don't use $MetaTags
   * See https://github.com/w3c/webappsec-csp/issues/348 for a good discussion on this and possible inclusion of CSPRO in metatags
   * @returns string
   */
  public function CspMetaTags()
  {
      $tags = [];

      if (!$this->checkCanRun()) {
          return "";
      }

      $stage = Versioned::current_stage();

      // check if request on the Live stage
      $is_live = ($stage == Versioned::get_live_stage());

      // get the default policy
      $policy = CspPolicy::getDefaultBasePolicy($is_live, CspPolicy::POLICY_DELIVERY_METHOD_METATAG);
      if (!empty($policy->ID) && ($data = $policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_METATAG))) {
          $tags[] = "<meta http-equiv=\"" . htmlspecialchars($data['header']) . "\" content=\"" . htmlspecialchars($data['policy_string']) . "\">";
      }

      // check for a specific page based policy
      if ($this->owner instanceof SiteTree) {
          $page_policy = CspPolicy::getPagePolicy($this->owner, $is_live, CspPolicy::POLICY_DELIVERY_METHOD_METATAG);
          if (!empty($page_policy->ID) && ($data = $page_policy->HeaderValues(1, CspPolicy::POLICY_DELIVERY_METHOD_METATAG))) {
              $tags[] = "<meta http-equiv=\"" . htmlspecialchars($data['header']) . "\" content=\"" . htmlspecialchars($data['policy_string']) . "\">";
          }
      }

      if(!empty($tags)) {
        return DBField::create_field( HTMLText::class, implode("\n", $tags) );
      }

      return "";

  }
}
