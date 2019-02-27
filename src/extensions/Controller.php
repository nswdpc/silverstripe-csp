<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use CspPolicy;
use Extension;
use Director;
use Config;
use ModelAdmin;
use SS_Log;
use SS_HTTPResponse;
use Versioned;
use LeftAndMain;
use ContentController;

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
    $run_in_admin = Config::inst()->get( CspPolicy::class , 'run_in_admin');
    $is_in_admin = $this->owner instanceof LeftAndMain;
    $whitelisted_controllers = Config::inst()->get( CspPolicy::class, 'whitelisted_controllers');
    if( !$run_in_admin && $is_in_admin ) {
      //SS_Log::log( "Not running in admin:" . get_class($this->owner), SS_Log::DEBUG);
      return false;
    }

    if( is_array($whitelisted_controllers) && in_array(get_class($this->owner), $whitelisted_controllers) ) {
      //SS_Log::log( "Not running in whitelisted controller:" . get_class($this->owner), SS_Log::DEBUG);
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
    if($response && !($response instanceof SS_HTTPResponse)) {
      return;
    }

    $stage = Versioned::current_stage();

    // check if request on the Live stage
    $is_live = ($stage == Versioned::get_live_stage());

    // only get enabled policy/directives
    $enabled_policy = $enabled_directives = 1;

    // get the default policy
    $policy = CspPolicy::getDefaultBasePolicy($is_live, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);

    // check for Page specific policies
    if($this->owner instanceof ContentController && ($data = $this->owner->data())) {
      $page_policy = CspPolicy::getPagePolicy($data, $is_live, CspPolicy::POLICY_DELIVERY_METHOD_HEADER);
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
    if($policy instanceof CspPolicy && ($data = $policy->HeaderValues($enabled_directives))) {
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
