<?php
/**
 * A Content Security Policy rule record
 * @author james.ellis@dpc.nsw.gov.au
 */
class CspRule extends \DataObject {
	
	/**
	 * Singular name for CMS
	 * @var string
	 */
	private static $singular_name = 'Rule';
	private static $plural_name = 'Rules';
	
	/**
	 * Database fields
	 * @var array
	 */
	private static $db = array(
		'Policy' => 'Text',
		'IsDefault' => 'Boolean',
		'ReportOnly' => 'Boolean',
		'AlternateReportURI' => 'Varchar(255)',// alternate reporting URI to your own controller/URI
		'DeliveryMethod' => 'Enum(\'Header,MetaTag\')'
	);
	
	public static function getDefaultRecord() {
		return \CspRule::get()->filter('IsDefault', 1)->first();
	}
	
	/**
	 * CMS Fields
	 * @return FieldList
	 */
	public function getCMSFields()
	{
		$fields = parent::getCMSFields();
		$fields->addFieldToTab(
			'Root.Main',
			\OptionsetField::create('DeliveryMethod', 'Delivery Method', [ 'Header' => 'Via an HTTP Header',  'MetaTag' => 'As a meta tag' ])
		);
		return $fields;
	}
	
	/**
	 * Event handler called before writing to the database.
	 */
	public function onBeforeWrite()
	{
		parent::onBeforeWrite();
		if($this->IsDefault == 1) {
			// set other records to not-default
			DB::query("UPDATE `ContentSecurityPolicy` SET IsDefault = 0 WHERE IsDefault = 1 AND ID <> " . Convert::raw2sql($this->ID));
		}
	}
}
