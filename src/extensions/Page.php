<?php
namespace NSWDPC\Utilities\ContentSecurityPolicy;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;

/**
 * Provides the ability to choose an extra CSP to use in addition to the default policy, if set
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Multiple_content_security_policies
 * @author james.ellis@dpc.nsw.gov.au
 */
class PageExtension extends DataExtension {

  /**
   * Has_one relationship
   * @var array
   */
  private static $has_one = [
    'CspPolicy' => Policy::class, // a page can have a CSP
  ];


  /**
   * Update Fields
   * @return FieldList
   */
  public function updateCMSFields(FieldList $fields)
  {
    $owner = $this->owner;
    $fields->addFieldToTab(
      'Root.CSP',
      DropdownField::create(
        'CspPolicyID',
        'Content Security Policy',
        Policy::get()->sort('Title ASC')->filter('Enabled', 1)->exclude('IsBasePolicy', 1)->map('ID','Title')
      )->setEmptyString('')
      ->setDescription( _t('ContentSecurityPolicy.ADDITION_SECURITY_POLICY', 'Choose an additional Content Security Policy to apply on this page only.<br>Adding additional policies can only further restrict the capabilities of the protected resource.') )
    );
    return $fields;
  }

}
