<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use Silverstripe\Core\Extension;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Versioned\Versioned;
use SilverStripe\View\HTML;
use SilverStripe\ORM\FieldType\DBHTMLText;
use SilverStripe\ORM\FieldType\DBField;

/**
 * Provides an extension method so that the SiteTree can gather the CSP meta tag if that is set
 * @author james.ellis@dpc.nsw.gov.au
 */
class SiteTreeExtension extends Extension
{

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

    /**
     * Check to see if a meta tag can be returned
     */
    private function checkCanRun()
    {
        $whitelisted_controllers = Config::inst()->get(Policy::class, 'whitelisted_controllers');
        $controller = Controller::curr();
        if (!$controller) {
            // no current controller
            return false;
        }

        if (is_array($whitelisted_controllers) && in_array(get_class($controller), $whitelisted_controllers)) {
            // allow through without MetaTags
            return false;
        }

        return true;
    }

    /**
     * Extension hook, see {@link SilverStripe\CMS\Model\SiteTree::MetaTags}
     * @returns void
     */
    public function MetaTags(&$tags)
    {
        $csp_tags = $this->CspMetaTags();
        $tags = $tags . "\n" . $csp_tags;
    }

    /**
     * Note that reporting is ignored/disallowed when using a meta tag. Only the header Content-Security-Policy is allowed.
     * In your template this can be called directly by adding $CspMetaTags if you don't use $MetaTags
     * See https://github.com/w3c/webappsec-csp/issues/348 for a good discussion on this and possible inclusion of CSPRO in metatags
     * @returns string
     */
    public function CspMetaTags()
    {
        $tags = [];

        if (!$this->checkCanRun()) {
            return "";
        }

        $stage = Versioned::get_stage();
        // check if request on the Live stage
        $is_live = ($stage == Versioned::LIVE);

        // get the default policy
        $policy = Policy::getDefaultBasePolicy($is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
        if (!empty($policy->ID) && ($data = $policy->HeaderValues(1, Policy::POLICY_DELIVERY_METHOD_METATAG))) {
            $tags[] = HTML::createTag('meta', [
                'http-equiv' => $data['header'],
                'content' => $data['policy_string'],
            ]);
        }

        // check for a specific page based policy
        if ($this->owner instanceof SiteTree) {
            $page_policy = Policy::getPagePolicy($this->owner, $is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
            if (!empty($page_policy->ID) && ($data = $page_policy->HeaderValues(1, Policy::POLICY_DELIVERY_METHOD_METATAG))) {
                $tags[] = HTML::createTag('meta', [
                    'http-equiv' => $data['header'],
                    'content' => $data['policy_string'],
                ]);
            }
        }

        if (!empty($tags)) {
            return DBField::create_field(DBHTMLText::class, implode("\n", $tags));
        }

        return "";
    }
}
