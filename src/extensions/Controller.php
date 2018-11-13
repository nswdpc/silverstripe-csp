<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use Silverstripe\Core\Extension;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Admin\ModelAdmin;
// use SS_Log;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Admin\LeftAndMain;

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
    if($response && !($response instanceof HTTPResponse)) {
      return;
    }

    $stage = Versioned::current_stage();

    // get the default policy
    $policy = Policy::get()->filter( ['Enabled' => 1, 'DeliveryMethod' => 'Header'] );
    if($stage == Versioned::get_live_stage()) {
      // live
      $policy = $policy->filter('IsLive', 1);
    }
    $policy = $policy->first();

    if(empty($policy->ID)) {
      return ;
    }

    if($data = $policy->HeaderValues()) {
      // Add the Report-To header for all
      if(!empty($data['reporting'])) {
        $response->addHeader("Report-To", json_encode($data['reporting'], JSON_UNESCAPED_SLASHES));
      }
      $response->addHeader($data['header'], $data['policy_string']);
    }
    return;
  }
}
