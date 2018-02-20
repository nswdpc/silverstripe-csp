<?php
namespace NSWDPC\CSP;
/**
 * Admin for managing Content Security Policy and Vuilation Reports
 * @author james.ellis@dpc.nsw.gov.au
 */
class ModelAdmin extends \ModelAdmin {
	private static $url_segment = 'content-security-policy';
	private static $menu_title = 'CSP';
	private static $managed_models = array(
		'ContentSecurityPolicy',
		'CspViolationReport',
	);

}
