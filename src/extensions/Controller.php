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

    // ADMIN check
    $is_in_admin = $this->owner instanceof LeftAndMain;
    if( $is_in_admin ) {
      $run_in_admin = Config::inst()->get( CspPolicy::class , 'run_in_admin');
      return $run_in_admin;
    }

    $whitelisted_controllers = Config::inst()->get( CspPolicy::class, 'whitelisted_controllers');
    if( is_array($whitelisted_controllers) && in_array(get_class($this->owner), $whitelisted_controllers) ) {
      return false;
    }

    if($this->owner instanceof ContentController ) {
      // all ContentControllers are enabled
      return true;
    }

    /**
     * Any controller that implements this method can return it
     * This can be accessed either via a trait or via applying the ContentSecurityPolicyEnable extension to a Controller type
     */
    if(method_exists( $this->owner, 'EnableContentSecurityPolicy')
        || $this->owner->hasMethod('EnableContentSecurityPolicy')) {
        return $this->owner->EnableContentSecurityPolicy();
    }

    // Do not enable by default on all controllers
    return false;
  }

  public function onAfterInit() {

    // Don't go in a loop reporting to the Reporting Endpoint controller from the Reporting Endpoint controller!
    if($this->owner instanceof ReportingEndpoint) {
      return;
    }

    // check if we can proceed
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
        /**
         * See: https://www.w3.org/TR/reporting/
         * "The header’s value is interpreted as a JSON-formatted array of objects without the outer [ and ], as described in Section 4 of [HTTP-JFV]."
         */
        $encoded_report_to = json_encode($data['reporting'], JSON_UNESCAPED_SLASHES);
        $encoded_report_to = trim($encoded_report_to, "[]");
        $response->addHeader( CspPolicy::HEADER_REPORT_TO, $encoded_report_to );
      }
      if(!empty($data['nel'])) {
        $response->addHeader( CspPolicy::HEADER_NEL, json_encode($data['nel'], JSON_UNESCAPED_SLASHES) );
      }
      // the relevant CSP-header with its values
      $response->addHeader($data['header'], $data['policy_string']);
    }

    return;
  }
}
