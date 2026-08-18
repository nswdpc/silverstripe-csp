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
 * Provides an extension method so that the SiteTree can gather the CSP meta tag if that is set
 * @property int $CspPolicyID
 * @method \NSWDPC\Utilities\ContentSecurityPolicy\Policy CspPolicy()
 * @extends \SilverStripe\Core\Extension<(\SilverStripe\CMS\Model\SiteTree & static)>
 */
class SiteTreeExtension extends Extension
{
    /**
     * Has_one relationship
     * @config
     */
    private static array $has_one = [
        'CspPolicy' => Policy::class, // a page can have a CSP
    ];

    /**
     * Update CMS Fields
     */
    public function updateCmsFields(FieldList $fields)
    {
        $fields->removeByName(['CspPolicyID']);
    }

    /**
     * Update Settings Fields
     */
    public function updateSettingsFields(FieldList $fields)
    {
        $available_policies = Policy::get()->sort('Title ASC')->filter('Enabled', 1)->exclude('IsBasePolicy', 1);
        $fields->removeByName(['CspPolicyID']);
        if ($available_policies->count() == 0) {
            $fields->addFieldToTab(
                'Root.CSP',
                LiteralField::create(
                    'CspPolicyNoneFound',
                    '<p class="message info">' .
                        htmlspecialchars(_t(
                            'ContentSecurityPolicy.NO_AVAILABLE_EXTRA_POLICIES',
                            'There are no extra Content Security Polices. To fix this, define a new policy in the CSP administration area or ask an administrator to do this and it will appear here'
                        ))
                    . "</p>"
                )
            );
        } else {
            $fields->addFieldToTab(
                'Root.CSP',
                DropdownField::create(
                    'CspPolicyID',
                    _t(
                        'ContentSecurityPolicy.CONTENT_SECURITY_POLICY_CHOOSE',
                        'Content Security Policy',
                    ),
                    $available_policies->map('ID', 'Title')
                )->setEmptyString('')
                    ->setDescription(
                        nl2br(htmlspecialchars(_t(
                            'ContentSecurityPolicy.ADDITION_SECURITY_POLICY',
                            "Choose an additional Content Security Policy to apply on this page only."
                            . "\n"
                            . "Adding additional policies can only further restrict the capabilities of the protected resource."
                        )))
                    )
            );
        }
    }

    /**
     * Check to see if a meta tag can be returned
     */
    private function checkCanRun(): bool
    {
        $controller = Controller::curr();
        if (!($controller instanceof Controller)) {
            // no current controller
            return false;
        } else {
            // Configured controllers with no CSP
            return !Policy::controllerWithoutCsp($controller);
        }
    }

    /**
     * Extension hook, see {@link SilverStripe\CMS\Model\SiteTree::MetaTags}
     * @deprecated Delivery of CSP via metatags will be removed in a future major version
     * @returns void
     */
    public function updateMetaTags(&$tags)
    {
        $csp_tags = $this->CspMetaTags();
        $tags = $tags . "\n" . $csp_tags;
    }

    /**
     * Note that reporting is ignored/disallowed when using a meta tag. Only the header Content-Security-Policy is allowed.
     * In your template this can be called directly by adding $CspMetaTags if you don't use $MetaTags
     * See https://github.com/w3c/webappsec-csp/issues/348 for a good discussion on this and possible inclusion of CSPRO in metatags
     * @deprecated Delivery of CSP via metatags will be removed in a future major version
     * @returns string
     */
    public function CspMetaTags(): string|\SilverStripe\ORM\FieldType\DBField
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
        if (!empty($policy->ID) && ($data = $policy->getPolicyData(true))) {
            $tags[] = HTML::createTag('meta', [
                'http-equiv' => $data['header'],
                'content' => $data['policy_string'],
            ]);
        }

        // check for a specific page based policy
        if ($this->getOwner() instanceof SiteTree) {
            $page_policy = Policy::getPagePolicy($this->getOwner(), $is_live, Policy::POLICY_DELIVERY_METHOD_METATAG);
            if (!empty($page_policy->ID) && ($data = $page_policy->getPolicyData(true))) {
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
