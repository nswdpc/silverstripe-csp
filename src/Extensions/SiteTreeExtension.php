<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Versioned\Versioned;
use SilverStripe\View\HTML;
use SilverStripe\ORM\FieldType\DBHTMLText;
use SilverStripe\ORM\FieldType\DBField;

/**
 * Allow selection of a page-specific CSP
 */
class SiteTreeExtension extends Extension
{

    /**
     * Has_one relationship
     * @var array
     * @config
     */
    private static $has_one = [
        'CspPolicy' => Policy::class, // a page can have a CSP
    ];

    /**
     * Update Fields
     * @return FieldList
     */
    public function updateSettingsFields(FieldList $fields)
    {
        $available_policies = Policy::get()->sort('Title ASC')->filter('Enabled', 1)->exclude('IsBasePolicy', 1);
        if($available_policies->count() == 0) {
            $fields->removeByName('CspPolicyID');
            $fields->addFieldToTab(
                'Root.CSP',
                LiteralField::create(
                    'CspPolicyNoneFound',
                    '<p class="message info">' .
                        _t(
                            'ContentSecurityPolicy.NO_AVAILABLE_EXTRA_POLICIES',
                            'There are no extra Content Security Polices. To fix this, define a new policy in the CSP administration area or ask an administrator to do this and it will appear here'
                        )
                    . "</p>"
                )
            );
        } else {
            $fields->addFieldToTab(
                'Root.CSP',
                DropdownField::create(
                    'CspPolicyID',
                    'Content Security Policy',
                    $available_policies->map('ID', 'Title')
                )->setEmptyString('')
                    ->setDescription(
                        _t(
                            'ContentSecurityPolicy.ADDITION_SECURITY_POLICY',
                            'Choose an additional Content Security Policy to apply on this page only.<br>Adding additional policies can only further restrict the capabilities of the protected resource.'
                        )
                )
            );
        }
        return $fields;
    }

}
