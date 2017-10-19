<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    class Helpers {
        
        /**
         * Simple cookie setter helper method that automatically adds host and path
         *
         * @since   1.4
         * @return  void
         */
        public static function set_cookie($name, $value, $expiry) {
            
            setcookie($name, $value, $expiry, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN);
            setcookie($name, $value, $expiry, ADMIN_COOKIE_PATH, COOKIE_DOMAIN);
            setcookie($name, $value, $expiry, COOKIEPATH, COOKIE_DOMAIN);
            if ( COOKIEPATH != SITECOOKIEPATH ) {
                setcookie($name, $value, $expiry, SITECOOKIEPATH, COOKIE_DOMAIN);
            }

            Logger::write_log("DEBUG", "Setting cookie $name with value $value");

        }

        /**
         * Simple cookie getter helper
         *
         * @since   1.4
         * @return  mixed   cookie or if not found false
         */
        public static function get_cookie($name) {

            if(!isset($_COOKIE[$name])) {
                return false;
            }

            return $_COOKIE[$name];

        }
    }

?>