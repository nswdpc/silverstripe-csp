<?php
namespace NSWDPC\CSP;

class Backend extends \Requirements_Backend {
	/**
	 * Register the given JavaScript file as required.
	 *
	 * @param string $file Relative to docroot
	 */
	public function javascript($file, $attributes = []) {
		$this->javascript[$file] = array(
			"attributes" => $attributes
		);
	}
	
	/**
	 * This is basically the same as standard requirements, with the addition of attribute support in scripts
	 *
	 * @param string $templateFile No longer used, only retained for compatibility
	 * @param string $content      HTML content that has already been parsed from the $templateFile
	 *                             through {@link SSViewer}
	 * @return string HTML content augmented with the requirements tags
	 */
	public function includeInHTML($templateFile, $content) {
		if(
			(strpos($content, '</head>') !== false || strpos($content, '</head ') !== false)
			&& ($this->css || $this->javascript || $this->customCSS || $this->customScript || $this->customHeadTags)
		) {
			$requirements = '';
			$jsRequirements = '';

			// Combine files - updates $this->javascript and $this->css
			$this->process_combined_files();

			foreach(array_diff_key($this->javascript,$this->blocked) as $file => $attributes) {
				$path = Convert::raw2xml($this->path_for_file($file));
				if($path) {
					$script_attributes = "";
					if(!empty($attributes) && is_array($attributes)) {
						$attributes = Convert::raw2htmlatt($attributes);
						foreach($attributes as $attribute_name => $attribute_value) {
							$script_attributes .= " {$attribute_name}=\"{$attribute_value}\"";
						}
					}
					$jsRequirements .= "<script type=\"text/javascript\" src=\"$path\"{$script_attributes}></script>\n";
				}
			}

			// Add all inline JavaScript *after* including external files they might rely on
			if($this->customScript) {
				foreach(array_diff_key($this->customScript,$this->blocked) as $script) {
					$jsRequirements .= "<script type=\"text/javascript\">\n//<![CDATA[\n";
					$jsRequirements .= "$script\n";
					$jsRequirements .= "\n//]]>\n</script>\n";
				}
			}

			foreach(array_diff_key($this->css,$this->blocked) as $file => $params) {
				$path = Convert::raw2xml($this->path_for_file($file));
				if($path) {
					$media = (isset($params['media']) && !empty($params['media']))
						? " media=\"{$params['media']}\"" : "";
					$requirements .= "<link rel=\"stylesheet\" type=\"text/css\"{$media} href=\"$path\" />\n";
				}
			}

			foreach(array_diff_key($this->customCSS, $this->blocked) as $css) {
				$requirements .= "<style type=\"text/css\">\n$css\n</style>\n";
			}

			foreach(array_diff_key($this->customHeadTags,$this->blocked) as $customHeadTag) {
				$requirements .= "$customHeadTag\n";
			}

			if ($this->force_js_to_bottom) {
				// Remove all newlines from code to preserve layout
				$jsRequirements = preg_replace('/>\n*/', '>', $jsRequirements);

				// Forcefully put the scripts at the bottom of the body instead of before the first
				// script tag.
				$content = preg_replace("/(<\/body[^>]*>)/i", $jsRequirements . "\\1", $content);
				
				// Put CSS at the bottom of the head
				$content = preg_replace("/(<\/head>)/i", $requirements . "\\1", $content);				
			} elseif($this->write_js_to_body) {
				// Remove all newlines from code to preserve layout
				$jsRequirements = preg_replace('/>\n*/', '>', $jsRequirements);
				
				// If your template already has script tags in the body, then we try to put our script
				// tags just before those. Otherwise, we put it at the bottom.
				$p2 = stripos($content, '<body');
				$p1 = stripos($content, '<script', $p2);
				
				$commentTags = array();
				$canWriteToBody = ($p1 !== false)
					&&
					// Check that the script tag is not inside a html comment tag
					!(
						preg_match('/.*(?|(<!--)|(-->))/U', $content, $commentTags, 0, $p1)
						&& 
						$commentTags[1] == '-->'
					);

				if($canWriteToBody) {
					$content = substr($content,0,$p1) . $jsRequirements . substr($content,$p1);
				} else {
					$content = preg_replace("/(<\/body[^>]*>)/i", $jsRequirements . "\\1", $content);
				}

				// Put CSS at the bottom of the head
				$content = preg_replace("/(<\/head>)/i", $requirements . "\\1", $content);
			} else {
				$content = preg_replace("/(<\/head>)/i", $requirements . "\\1", $content);
				$content = preg_replace("/(<\/head>)/i", $jsRequirements . "\\1", $content);
			}
		}

		return $content;
	}
}
