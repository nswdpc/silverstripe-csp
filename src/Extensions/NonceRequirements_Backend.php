<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\View\Requirements_Backend;
use SilverStripe\View\HTML;

/**
 * This is a custom requirements backend that injects the global nonce value
 * into a) custom scripts and b) custom CSS
 * As the core requirements backend does not allow custom attributes for custom CSS
 * the custom CSS with nonce added is added via getCustomHeadTags
 */
class NonceRequirements_Backend extends Requirements_Backend
{

    /**
     * @inheritdoc
     * Divert to customScriptWithAttributes to ensure the nonce attribute is set
     */
    #[\Override]
    public function customScript($script, $uniquenessID = null)
    {
        if(Policy::config()->get('nonce_injection_method') == Policy::NONCE_INJECT_VIA_REQUIREMENTS) {
            $attributes = [];
            self::customScriptWithAttributes($script, $attributes, $uniquenessID);
        } else {
            parent::customScript($script, $uniquenessID);
        }
    }

    /**
     * @inheritdoc
     * Set the global nonce attribute value
     */
    #[\Override]
    public function customScriptWithAttributes(string $script, array $attributes = [], string|int|null $uniquenessID = null)
    {
        if(Policy::config()->get('nonce_injection_method') == Policy::NONCE_INJECT_VIA_REQUIREMENTS) {
            $attributes['nonce'] = Nonce::getNonce();
        }

        parent::customScriptWithAttributes($script, $attributes, $uniquenessID);
    }

    /**
     * Return no custom CSS here, as the core requirements doesn't
     * allow custom attributes for style tags
     */
    #[\Override]
    public function getCustomCSS()
    {
        if(Policy::config()->get('nonce_injection_method') == Policy::NONCE_INJECT_VIA_REQUIREMENTS) {
            // See getCustomHeadTags + getCustomCSSWithNonce
            return [];
        } else {
            return parent::getCustomCSS();
        }
    }

    /**
     * Return custom CSS with nonce attribute added
     */
    public function getCustomCSSWithNonce(): array
    {
        $customCSS = array_diff_key($this->customCSS ?? [], $this->blocked);
        $tags = [];
        foreach($customCSS as $css) {
            $tags[] = HTML::createTag(
                'style',
                [
                    'type' => 'text/css',
                    'nonce' => Nonce::getNonce()
                ],
                "\n{$css}\n"
            );
        }

        return $tags;
    }

    /**
     * @inheritdoc
     * Returns custom head tags, with custom CSS included
     */
    #[\Override]
    public function getCustomHeadTags()
    {
        $styleTags = [];
        if(Policy::config()->get('nonce_injection_method') == Policy::NONCE_INJECT_VIA_REQUIREMENTS) {
            $styleTags = $this->getCustomCSSWithNonce();
        }

        $customHeadTags = array_diff_key($this->customHeadTags ?? [], $this->blocked);
        return array_merge($styleTags, $customHeadTags);
    }

}
