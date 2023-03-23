<?php

namespace NSWDPC\Utilities\ContentSecurityPolicy;

use SilverStripe\Dev\Deprecation;
use SilverStripe\View\Requirements_Backend;
use SilverStripe\Core\Config\Config;
use SilverStripe\View\HTML;

class NonceRequirements_Backend extends Requirements_Backend
{

    /**
     * Update the given HTML content with the appropriate include tags for the registered
     * requirements. Needs to receive a valid HTML/XHTML template in the $content parameter,
     * including a head and body tag.
     *
     * @param string $content HTML content that has already been parsed from the $templateFile
     *                             through {@link SSViewer}
     * @return string HTML content augmented with the requirements tags
     */
    public function includeInHTML($content)
    {
        if (func_num_args() > 1) {
            Deprecation::notice(
                '5.0',
                '$templateFile argument is deprecated. includeInHTML takes a sole $content parameter now.'
            );
            $content = func_get_arg(1);
        }

        // Skip if content isn't injectable, or there is nothing to inject
        $tagsAvailable = preg_match('#</head\b#', $content);
        $hasFiles = $this->css || $this->javascript || $this->customCSS || $this->customScript || $this->customHeadTags;
        if (!$tagsAvailable || !$hasFiles) {
            return $content;
        }
        $requirements = '';
        $jsRequirements = '';

        // Combine files - updates $this->javascript and $this->css
        $this->processCombinedFiles();

        // Script tags for js links
        foreach ($this->getJavascript() as $file => $attributes) {
            // Build html attributes
            $htmlAttributes = [
                'type' => isset($attributes['type']) ? $attributes['type'] : "application/javascript",
                'src' => $this->pathForFile($file),
            ];
            if (!empty($attributes['async'])) {
                $htmlAttributes['async'] = 'async';
            }
            if (!empty($attributes['defer'])) {
                $htmlAttributes['defer'] = 'defer';
            }
            if (!empty($attributes['integrity'])) {
                $htmlAttributes['integrity'] = $attributes['integrity'];
            }
            if (!empty($attributes['crossorigin'])) {
                $htmlAttributes['crossorigin'] = $attributes['crossorigin'];
            }
            $tag = 'script';
            Nonce::addToAttributes($tag, $htmlAttributes);
            $jsRequirements .= HTML::createTag($tag, $htmlAttributes);
            $jsRequirements .= "\n";
        }

        // Add all inline JavaScript *after* including external files they might rely on
        foreach ($this->getCustomScripts() as $script) {
            $attributes = [
                'type' => 'application/javascript'
            ];
            $tag = 'script';
            Nonce::addToAttributes($tag, $attributes);
            $jsRequirements .= HTML::createTag(
                $tag,
                $attributes,
                "//<![CDATA[\n{$script}\n//]]>"
            );
            $jsRequirements .= "\n";
        }

        // CSS file links
        foreach ($this->getCSS() as $file => $params) {
            $htmlAttributes = [
                'rel' => 'stylesheet',
                'type' => 'text/css',
                'href' => $this->pathForFile($file),
            ];
            if (!empty($params['media'])) {
                $htmlAttributes['media'] = $params['media'];
            }
            if (!empty($params['integrity'])) {
                $htmlAttributes['integrity'] = $params['integrity'];
            }
            if (!empty($params['crossorigin'])) {
                $htmlAttributes['crossorigin'] = $params['crossorigin'];
            }
            $tag = 'link';
            Nonce::addToAttributes($tag, $htmlAttributes);
            $requirements .= HTML::createTag($tag, $htmlAttributes);
            $requirements .= "\n";
        }

        // Literal custom CSS content
        foreach ($this->getCustomCSS() as $css) {
            $attributes = [
                'type' => 'text/css'
            ];
            $tag = 'style';
            Nonce::addToAttributes($tag, $attributes);
            $requirements .= HTML::createTag(
                $tag,
                $attributes,
                "\n{$css}\n"
            );
            $requirements .= "\n";
        }

        foreach ($this->getCustomHeadTags() as $customHeadTag) {
            $requirements .= "{$customHeadTag}\n";
        }

        // Inject CSS  into body
        $content = $this->insertTagsIntoHead($requirements, $content);

        // Inject scripts
        if ($this->getForceJSToBottom()) {
            $content = $this->insertScriptsAtBottom($jsRequirements, $content);
        } elseif ($this->getWriteJavascriptToBody()) {
            $content = $this->insertScriptsIntoBody($jsRequirements, $content);
        } else {
            $content = $this->insertTagsIntoHead($jsRequirements, $content);
        }
        return $content;
    }

}
