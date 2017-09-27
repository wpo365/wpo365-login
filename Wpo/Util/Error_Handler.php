<?php

    namespace Wpo\Util;

    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Util/Helpers.php");

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

            $messages_arr = NULL;

            // Check to see whether there are any login messages
            if(Helpers::get_cookie("WPO365_LOGIN_ERR_MSGS") !== false) {
                
                $messages_arr = explode(";", base64_decode($_COOKIE["WPO365_LOGIN_ERR_MSGS"]));

            }
            else {

                return;

            }

            // Get messages from the login messages container
            $result = "";
            foreach($messages_arr as $msg) {

                $result .= "<p class=\"message\">" . $msg . "</p><br />";

            }

            // Empty the login messages container
            Helpers::set_cookie("WPO365_LOGIN_ERR_MSGS", "", time() - 3600);
            
            // Return messages to display to hook
            return $result;
        }

        public static function add_login_message($message) {

            $messages_arr = NULL;

            // Create login messages container if it does not exist
            if(Helpers::get_cookie("WPO365_LOGIN_ERR_MSGS") !== false) {
                
                $messages_arr = explode(";", base64_decode($_COOKIE["WPO365_LOGIN_ERR_MSGS"]));

            }
            else {

                $messages_arr = array();

            }

            // Add new message to array of existing messages
            $messages_arr[] = $message;

            // Update cookie
            Helpers::set_cookie("WPO365_LOGIN_ERR_MSGS", base64_encode(implode(";", $messages_arr)), time() + 120);
        }
    }

?>