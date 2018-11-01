<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use CspRule;
use Extension;
use Versioned;

/**
 * Provides an extension method so that the SiteTree can gather the CSP meta tag if that is set
 * @author james.ellis@dpc.nsw.gov.au
 */
class SiteTree extends Extension {

  public function MetaTags(&$tags) {
    // get the default policy
    $policy = CspRule::get()->filter( ['Enabled' => 1, 'DeliveryMethod' => 'MetaTag'] )->first();
    if($stage == Versioned::get_live_stage()) {
      // live
      $policy = $policy->filter('IsLive', 1);
    }
    $policy = $policy->first();
    if(empty($policy->ID)) {
      return;
    }

    $data = $policy->HeaderValues();

    // Note that reporting is ignored when using a meta tag
    $tags .= "<meta http-equiv=\"{$data['header']}\" content=\"" . $data['policy_string'] . "\">\n";

  }
}
