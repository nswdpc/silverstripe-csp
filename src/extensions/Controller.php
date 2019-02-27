<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use Silverstripe\Core\Extension;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Admin\LeftAndMain;
use SilverStripe\CMS\Controllers\ContentController;

/**
 * Provides an extension method so that the Controller can set the relevant CSP header
 * @author james.ellis@dpc.nsw.gov.au
 * @todo report-uri is deprecated, report-to is the new thang but browsers don't fully support report-to yet
 */
class ControllerExtension extends Extension {

  /**
   * Check to see if the current Controller allows a CSP header
   */
  private function checkCanRun() {
    $run_in_admin = Config::inst()->get( Policy::class , 'run_in_admin');
    $is_in_admin = $this->owner instanceof LeftAndMain;
    $whitelisted_controllers = Config::inst()->get( Policy::class, 'whitelisted_controllers');
    if( !$run_in_admin && $is_in_admin ) {
      return false;
    }

    if( is_array($whitelisted_controllers) && in_array(get_class($this->owner), $whitelisted_controllers) ) {
      return false;
    }

    if(!($this->owner instanceof ContentController) && !($this->owner instanceof LeftAndMain)) {
        // can only run in these controllers
        return false;
    }
    return true;
  }

  public function onAfterInit() {

    if(Director::is_cli()) {
      // Don't run when executing on the shell
      return;
    }

    if($this->owner instanceof ReportingEndpoint) {
      // Don't go in a loop reporting to the Reporting Endpoint controller from the Reporting Endpoint controller!
      return;
    }

    if(!$this->checkCanRun()) {
      return;
    }

    $response = $this->owner->getResponse();
    if($response && !($response instanceof HTTPResponse)) {
      return;
    }

    $stage = Versioned::get_stage();

    // check if request on the Live stage
    $is_live = ($stage == Versioned::LIVE);

    // only get enabled policy/directives
    $enabled_policy = $enabled_directives = 1;

    $policy = Policy::getDefaultBasePolicy($is_live, Policy::POLICY_DELIVERY_METHOD_HEADER);

    // check for Page specific policies
    if($this->owner instanceof ContentController && ($data = $this->owner->data())) {
      $page_policy = Policy::getPagePolicy($data, $is_live, Policy::POLICY_DELIVERY_METHOD_HEADER);
      if(!empty($page_policy->ID)) {
        if(!empty($policy->ID)) {
          /**
           * SS_HTTPResponse can't handle header names that are duplicated (which is allowed in the HTTP spec)
           * Workaround is to set the page policy for merging when HeaderValues() is called
           * Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Multiple_content_security_policies
           * Ref: https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
           */
          $policy->SetMergeFromPolicy($page_policy);
        } else {
          // the page policy is *the* policy
          $policy = $page_policy;
        }
      }
    }

    // Add the policy/reporting header values
    if($policy instanceof Policy && ($data = $policy->HeaderValues($enabled_directives))) {
      // Add the Report-To header for all
      if(!empty($data['reporting'])) {
        $response->addHeader("Report-To", json_encode($data['reporting']));
      }
      if(!empty($data['nel'])) {
        $response->addHeader("NEL", json_encode($data['nel']));
      }
      // the relevant CSP-header with its values
      $response->addHeader($data['header'], $data['policy_string']);
    }

    return;
  }
}
