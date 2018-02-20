<?php
namespace NSWDPC\CSP;
/**
 * Provides an extension method so that the SiteTree can gather the CSP meta tag if that is set
 * @author james.ellis@dpc.nsw.gov.au
 */
class SiteTree extends \Extension {
	
	public function MetaTags(&$tags) {
		// get the default policy
		$policy = \CspRule::get()->filter( ['IsDefault' => 1, 'DeliveryMethod' => 'MetaTag'] )->first();
		if(!empty($policy->ID)) {
			$tags .= "<meta http-equiv=\"Content-Security-Policy\" content=\"" . htmlspecialchars($policy->Policy) . "\">\n";
		}
	}
}
