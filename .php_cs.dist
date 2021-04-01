<?php
/**
 * Configuration file for https://github.com/FriendsOfPHP/PHP-CS-Fixer
 * Install with composer: $ composer global require friendsofphp/php-cs-fixer
 * Usage (in this directory) :  ~/.composer/vendor/bin/php-cs-fixer fix .
 */
$finder = PhpCsFixer\Finder::create()
            ->in(__DIR__);

return PhpCsFixer\Config::create()
        ->setRules([
            '@PSR2' => true,
            'array_indentation' => true,
            'array_syntax' => ['syntax' => 'short'],
            'blank_line_after_namespace' => true,
            'blank_line_after_opening_tag' => true,
            'full_opening_tag' => true,
            'no_closing_tag' => true,
        ])
        ->setIndent("    ")
        ->setFinder($finder);
