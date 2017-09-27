<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    class Error_Handler {

        /**
         * Checks for errors in the login messages container and display and unset immediatly after if any
         *
         * @since   1.0
         * @return  void
         */
        public static function check_for_login_messages() {

            // Don't log debug level if not explicitely requested
            if(!isset($_SESSION["WPO365_LOGIN_ERR_MSGS"])
                || empty($_SESSION["WPO365_LOGIN_ERR_MSGS"])
                || !is_array($_SESSION["WPO365_LOGIN_ERR_MSGS"])) {

                return;

            }

            // Get from the login messages container
            $result = "";
            foreach($_SESSION["WPO365_LOGIN_ERR_MSGS"] as $msg) {

                $result .= "<p class=\"message\">" . $msg . "</p><br />";

            }

            // Empty the login messages container
            unset($_SESSION["WPO365_LOGIN_ERR_MSGS"]);
            
            // Return messages to display to hook
            return $result;
        }

        public static function add_login_message($message) {

            // Create login messages container if it does not exist
            if(!isset($_SESSION["WPO365_LOGIN_ERR_MSGS"])
                || empty($_SESSION["WPO365_LOGIN_ERR_MSGS"])
                || !is_array($_SESSION["WPO365_LOGIN_ERR_MSGS"])) {

                $_SESSION["WPO365_LOGIN_ERR_MSGS"] = array();
                
            }

            // Add message to login messages container
            $_SESSION["WPO365_LOGIN_ERR_MSGS"][] = $message;
        }
    }

?>