<?php
    /**
     *  Plugin Name: WPO365 Login (personal use)
     *  Plugin URI: https://www.wpo365.com/downloads/wordpress-office-365-login/
     *  Github URI: https://github.com/wpo365/wpo365-login
     *  Description: Wordpress + Office 365 login allows Microsoft O365 users to seamlessly and securely log on to your corporate Wordpress intranet. The plugin will create a Wordpress user for each corporate user when logged on to Office 365 and thus avoiding the default Wordpress login screen: No username or password required.
     *  Version: 5.0
     *  Author: info@wpo365.com
     *  Author URI: https://www.wpo365.com
     *  License: GPL2+
     */
    
    // Prevent public access to this script
    defined( 'ABSPATH' ) or die( );

    $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] = '5.0';
    $GLOBALS[ 'WPO365_PLUGIN_DIR' ] = __DIR__;
    
    require __DIR__ . '/vendor/autoload.php';

    \Wpo\Wpo365_Login::getInstance();
    
    
    

    
        
    

    

    

   

    

?>