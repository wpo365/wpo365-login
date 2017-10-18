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
            
            $path = parse_url(get_option("siteurl"), PHP_URL_PATH);
            $setcookie_result = setcookie($name, $value, $expiry, $path, COOKIE_DOMAIN);

            Logger::write_log("DEBUG", "Setting cookie $name with value $value set for $path (" . get_option("siteurl") . ")" . ($setcookie_result === true ? " OK " : " NOK "));

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