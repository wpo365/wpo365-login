<?php
    // Init Wordpress
    define("WP_USE_THEMES", true);
    require(__DIR__ . "/../../../wp-load.php");

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Aad/Auth.php");

    use \Wpo\Aad\Auth;

    
    // Handle a redirect
    Auth::handle_redirect();

    // Catch all => If not redirected to state then redirect to login
    Auth::goodbye();

?>