<?php
namespace NSWDPC\CSP;
/**
 * Provides an extension method so that the Controller can set the relevant CSP header
 * @author james.ellis@dpc.nsw.gov.au
 */
class ControllerExtension extends \Extension {
	
	public function onAfterInit() {
		$response = $this->owner->getResponse();
		if($response && !($response instanceof SS_HTTPResponse)) {
			return;
		}
		
		// get the default policy
		$policy = \CspRule::get()->filter( ['IsDefault' => 1, 'DeliveryMethod' => 'Header'] )->first();
		if(empty($policy->ID)) {
			return ;
		}
		$response->addHeader('Content-Security-Policy', $policy->Policy);
		return;
	}
}
