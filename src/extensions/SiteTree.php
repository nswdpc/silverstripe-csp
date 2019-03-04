<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use Silverstripe\Core\Extension;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;

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
    'CspPolicy' => Policy::class, // a page can have a CSP
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
        Policy::get()->sort('Title ASC')->filter('Enabled', 1)->exclude('IsBasePolicy', 1)->map('ID','Title')
      )->setEmptyString('')
      ->setDescription( _t('ContentSecurityPolicy.ADDITION_SECURITY_POLICY', 'Choose an additional Content Security Policy to apply on this page only.<br>Adding additional policies can only further restrict the capabilities of the protected resource.') )
    );
    return $fields;
  }

  /**
   * Check to see if a meta tag can be returned
   */
  private function checkCanRun() {
    $whitelisted_controllers = Config::inst()->get( Policy::class, 'whitelisted_controllers');
    $controller = Controller::curr();
    if( is_array($whitelisted_controllers) && in_array(get_class($controller), $whitelisted_controllers) ) {
      return false;
    }
    return true;
  }

  /**
   * Note that reporting is ignored when using a meta tag
   */
  public function MetaTags(&$tags) {
    if(!$this->checkCanRun()) {
      return;
    }

    $stage = Versioned::get_stage();
    // check if request on the Live stage
    $is_live = ($stage == Versioned::LIVE);

    // get the default policy
    $policy = Policy::getDefaultBasePolicy($is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
    if(!empty($policy->ID)) {
      $data = $policy->HeaderValues();
      $tags .= "<meta http-equiv=\"{$data['header']}\" content=\"" . $data['policy_string'] . "\">\n";
    }

    // check for a specific page based policy
    if($this->owner instanceof SiteTree) {
      $page_policy = Policy::getPagePolicy($this->owner, $is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
      if(!empty($page_policy->ID) && ($data = $page_policy->HeaderValues())) {
        $tags .= "<meta http-equiv=\"{$data['header']}\" content=\"" . $data['policy_string'] . "\">\n";
      }
    }

  }
}
