<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Core\Extension;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Admin\LeftAndMain;
use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\CMS\Controllers\ModelAsController;
use SilverStripe\CMS\Model\SiteTree;

/**
 * Provides an extension method so that the Controller can set the relevant CSP header
 */
class ControllerExtension extends Extension
{

    public function onAfterInit()
    {

        // No response handling
        $response = $this->owner->getResponse();
        if ($response && !($response instanceof HTTPResponse)) {
            return;
        }

        // Don't go in a loop reporting to the Reporting Endpoint controller from the Reporting Endpoint controller!
        if ($this->owner instanceof ReportingEndpoint) {
            return;
        }

        // check if a policy can be applied
        if (!$canApply = Policy::checkCanApply($this->owner)) {
            return;
        }

        // check if request on the Live stage
        $stage = Versioned::get_stage();
        $is_live = ($stage == Versioned::LIVE);

        // only get enabled policy/directives
        $enabled_policy = $enabled_directives = true;

        // Set the CSP nonce for this request
        Nonce::getNonce();

        $policy = Policy::getDefaultBasePolicy($is_live, Policy::POLICY_DELIVERY_METHOD_HEADER);

        // check for Page specific policy
        if ($this->owner instanceof ContentController
            && ($data = $this->owner->data())
            && $data instanceof SiteTree) {
                $page_policy = Policy::getPagePolicy($data, $is_live, Policy::POLICY_DELIVERY_METHOD_HEADER);
                if (!empty($page_policy->ID)) {
                    if (!empty($policy->ID)) {
                        /**
                         * HTTPResponse can't handle header names that are duplicated (which is allowed in the HTTP spec)
                         * Workaround is to set the page policy for merging when getPolicyData() is called
                         * Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#Multiple_content_security_policies
                         * Ref: https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
                         */
                        $policy->setMergeFromPolicy($page_policy);
                    } else {
                        // the page policy is *the* policy
                        $policy = $page_policy;
                    }
                }
        }

        // Add the policy/reporting header values
        if ($policy instanceof Policy && ($data = $policy->getPolicyData($enabled_directives))) {
            // Report-To header
            // Add the Reporting-Endpoints header
            if (!empty($data['reporting_endpoints'])) {
                // Add Reporting-Endpoints header
                $response->addHeader(
                    Policy::HEADER_REPORTING_ENDPOINTS,
                    Policy::getReportingEndpointsHeader($data['reporting_endpoints'])
                );
            }
            if (!empty($data['nel'])) {
                // NEL is enabled
                $response->addHeader(
                    Policy::HEADER_REPORT_TO,
                    Policy::getReportToHeader($data['report_to'])
                );
                $response->addHeader(
                    "NEL",
                    json_encode($data['nel'], JSON_UNESCAPED_SLASHES)
                );
            }
            // the relevant CSP-header with its values
            $response->addHeader($data['header'], $data['policy_string']);
        }

        return;
    }
}
