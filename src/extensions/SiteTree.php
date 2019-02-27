<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use Silverstripe\Core\Extension;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;

/**
 * Provides an extension method so that the SiteTree can gather the CSP meta tag if that is set
 * @author james.ellis@dpc.nsw.gov.au
 */
class SiteTreeExtension extends Extension {

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

    $stage = Versioned::current_stage();
    // check if request on the Live stage
    $is_live = ($stage == Versioned::LIVE);

    // get the default policy
    $policy = Policy::getDefaultBasePolicy($is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
    if(!empty($policy->ID)) {
      $data = $policy->HeaderValues();
      $tags .= "<meta http-equiv=\"{$data['header']}\" content=\"" . $data['policy_string'] . "\">\n";
    }

    // check for a specific page based policy
    if($this->owner instanceof Page) {
      $page_policy = Policy::getPagePolicy($this->owner, $is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
      if(!empty($page_policy->ID) && ($data = $page_policy->HeaderValues())) {
        $tags .= "<meta http-equiv=\"{$data['header']}\" content=\"" . $data['policy_string'] . "\">\n";
      }
    }

  }
}
