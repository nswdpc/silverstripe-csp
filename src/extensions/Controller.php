<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use CspRule;
use Extension;
use Director;
use Config;
use ModelAdmin;
use SS_Log;
use SS_HTTPResponse;
use Versioned;

/**
 * Provides an extension method so that the Controller can set the relevant CSP header
 * @author james.ellis@dpc.nsw.gov.au
 * @todo report-uri is deprecated, report-to is the new thang but browsers don't fully support report-to yet
 */
class ControllerExtension extends Extension {

  public function onAfterInit() {

    if(Director::is_cli()) {
      // Don't run when executing on the shell
      return;
    }

    if($this->owner instanceof ReportingEndpoint) {
      // Don't go in a loop reporting to the Reporting Endpoint controller from the Reporting Endpoint controller!
      return;
    }


    $run_in_admin = Config::inst()->get( CspRule::class , 'run_in_admin');
    $blacklisted_controllers = Config::inst()->get( CspRule::class, 'blacklisted_controllers');
    if( (!$run_in_admin && $this->owner instanceof ModelAdmin)
      || (is_array($blacklisted_controllers) && in_array(get_class($this->owner), $blacklisted_controllers)) ) {
      //SS_Log::log( "Not running in:" . get_class($this->owner), SS_Log::DEBUG);
      return;
    }

    $response = $this->owner->getResponse();
    if($response && !($response instanceof SS_HTTPResponse)) {
      return;
    }

    $stage = Versioned::current_stage();

    // get the default policy
    $policy = CspRule::get()->filter( ['Enabled' => 1, 'DeliveryMethod' => 'Header'] );
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
