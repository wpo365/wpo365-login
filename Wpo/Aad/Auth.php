<?php
    namespace Wpo\Aad;

    // prevent public access to this script
    defined( 'ABSPATH' ) or die();

    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Util/Logger.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Util/Helpers.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Util/Error_Handler.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/User/User_Manager.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Firebase/JWT/JWT.php");

    
    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\Util\Error_Handler;
    use \Wpo\User\User_Manager;
    use \Firebase\JWT\JWT;
    
    class Auth {

        /**
         * Destroys any session and authenication artefacts and hooked up with wp_logout and should
         * therefore never be called directly to avoid endless loops etc.
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function destroy_session() {
            
            Logger::write_log("DEBUG", "Destroying session " . strtolower(basename($_SERVER['PHP_SELF'])));
            
            // destroy wpo session and cookies
            Helpers::set_cookie("WPO365_AUTH", "", time() -3600);

        }

        /**
         * Same as destroy_session but with redirect to login page
         *
         * @since   1.0
         * @return  void
         */
        public static function goodbye() {

            wp_logout(); // This will also call destroy_session because of wp_logout hook
            auth_redirect();

        }

        /**
         * Validates each incoming request to see whether user prior to request
         * was authenicated by Microsoft Office 365 / Azure AD.
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function validate_current_session() {

            // Verify whether new (id_tokens) tokens are received and if so process them
            if(isset($_POST["state"]) && isset($_POST["id_token"])) {
                \Wpo\Aad\Auth::process_openidconnect_token();
            }

            // Don't continue validation if user is already logged in and is a Wordpress-only user
            if(User_Manager::user_is_o365_user() === false) {
                
                return;
                
            }

            // If selected scenario is 'Internet' (2) then only continue with validation when access to backend is requested
            if(isset($GLOBALS["wpo365_options"]["auth_scenario"])
                && !empty($GLOBALS["wpo365_options"]["auth_scenario"])
                && $GLOBALS["wpo365_options"]["auth_scenario"] == "2"
                && !is_admin()) {

                    Logger::write_log("DEBUG", "Cancelling session validation for page " . strtolower(basename($_SERVER['PHP_SELF'])) . " because selected scenario is 'Internet'");
                    return;

            }
            
            Logger::write_log("DEBUG", "Validating session for page " . strtolower(basename($_SERVER['PHP_SELF'])));
            
            // Is the current page blacklisted and if yes cancel validation
            if(!empty($GLOBALS["wpo365_options"]["pages_blacklist"]) 
                &&  strpos(strtolower($GLOBALS["wpo365_options"]["pages_blacklist"]), 
                    strtolower(basename($_SERVER['PHP_SELF']))) !== false) {

                Logger::write_log("DEBUG", "Cancelling session validation for page " . strtolower(basename($_SERVER['PHP_SELF'])));

                return;

            }

            // Don't allow access to the front end when WPO365 is unconfigured
            if((empty($GLOBALS["wpo365_options"]["tenant_id"])
                || empty($GLOBALS["wpo365_options"]["application_id"])
                || empty($GLOBALS["wpo365_options"]["redirect_url"])) 
                && !is_admin()) {
                
                Logger::write_log("ERROR", "WPO365 not configured");
                Error_Handler::add_login_message(__("Wordpress + Office 365 login not configured yet. Please contact your System Administrator."));
                Auth::goodbye();

            }

            // Refresh user's authentication when session not yet validated
            if(Helpers::get_cookie("WPO365_AUTH") == false) { // no session data found

                wp_logout(); // logout but don't redirect to the login page
                Logger::write_log("DEBUG", "Session data invalid or incomplete found");
                Auth::get_openidconnect_and_oauth_token();

            }

            $wp_usr_id = User_Manager::get_user_id();
            
            // Session validated but something must have gone wrong because user cannot be retrieved
            if($wp_usr_id === false) {

                Error_Handler::add_login_message(__("Could not retrieve your login. Please contact your System Administrator."));
                Auth::goodbye();
            }

            $wp_usr = get_user_by("ID", $wp_usr_id);

            Logger::write_log("DEBUG", "User " . $wp_usr->ID . " successfully authenticated");
            
            if(!is_user_logged_in()) {

                wp_set_auth_cookie($wp_usr->ID, true);

            }

        }

        /**
         * Gets authorization and id_tokens from Microsoft authorization endpoint by redirecting the user. The
         * state parameter is used to restore the user's state (= requested page) when redirected back to Wordpress
         * 
         * NOTE The refresh token is not used because it cannot be used to authenticate a user (no id_token)
         * See https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code 
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function get_openidconnect_and_oauth_token() {

            $nonce = uniqid();
            Helpers::set_cookie("WPO365_NONCE", $nonce, time() + 120);

            $params = array(
                "client_id" => $GLOBALS["wpo365_options"]["application_id"],
                "response_type" => "id_token code",
                "redirect_uri" => $GLOBALS["wpo365_options"]["redirect_url"],
                "response_mode" => "form_post",
                "scope" => $GLOBALS["wpo365_options"]["scope"],
                "resource" => $GLOBALS["wpo365_options"]["application_id"], // basically the app is asking permissiong to access itself and 
                                                                            // this scenario is only supported when using applciation id instead of application id uri
                "state" => (isset($_SERVER["HTTPS"]) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
                "nonce" => $nonce
            );

            $authorizeUrl = "https://login.microsoftonline.com/" . $GLOBALS["wpo365_options"]["tenant_id"] . "/oauth2/authorize?" . http_build_query($params, "", "&");
            Logger::write_log("DEBUG", "Getting fresh id and authorization tokens: " . $authorizeUrl);

            // Redirect to Microsoft Authorization Endpoint
            wp_redirect($authorizeUrl);
            exit(); // exit after redirect
        }

        /**
         * Handles redirect from Microsofts authorization service and tries to detect
         * any wrong doing and if detected redirects wrong-doer to Wordpress login instead
         *
         * @since   1.0
         * @return  void
         */
         public static function process_openidconnect_token() {
            
            Logger::write_log("DEBUG", "Processing incoming OpenID Connect id_token");

            $id_token = Auth::decode_id_token();
        
            // Handle if token could not be processed or nonce is invalid
            if($id_token === false 
                || Helpers::get_cookie("WPO365_NONCE") === false 
                || $id_token->nonce != $_COOKIE["WPO365_NONCE"]) {

                Error_Handler::add_login_message(__("Your login might be tampered with. Please contact your System Administrator."));
                Logger::write_log("ERROR", "id token could not be processed and user will be redirected to default Wordpress login");

                Auth::goodbye();

            }
        
            // Delete the nonce cookie variable
            Helpers::set_cookie("WPO365_NONCE", "", time() -3600);
                    
            // Ensure user with the information found in the id_token
            $usr = User_Manager::ensure_user($id_token);
            
            // Handle if user could not be processed
            if($usr === false) {

                Error_Handler::add_login_message(__("Could not create or retrieve your login. Please contact your System Administrator."));
                Logger::write_log("ERROR", "Could not get or create Wordpress user");

                Auth::goodbye();
            }

            // User could log on and everything seems OK so let's restore his state
            Logger::write_log("DEBUG", "Redirecting to " . $_POST["state"]);
            wp_redirect($_POST["state"]);
            exit(); // Always exit after a redirect

        }

        /**
         * Unraffles the incoming JWT id_token with the help of Firebase\JWT and the tenant specific public keys available from Microsoft.
         * 
         * NOTE The refresh token is not used because it cannot be used to authenticate a user (no id_token)
         * See https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code 
         *
         * @since   1.0
         *
         * @return  void 
         */
        private static function decode_id_token() {

            Logger::write_log("DEBUG", "Processing an new id token");

            // Check whether an id_token is found in the posted payload
            if(!isset($_POST["id_token"])) {
                Logger::write_log("ERROR", "id token not found");
                return false;
            }

            // Get the token and get it's header for a first analysis
            $id_token = $_POST["id_token"];
            $jwt_decoder = new JWT();
            $header = $jwt_decoder::header($id_token);
            
            // Simple validation of the token's header
            if(!isset($header->kid) || !isset($header->alg)) {

                Logger::write_log("ERROR", "JWT header is missing so stop here");
                return false;

            }

            // Discover tenant specific public keys
            $keys = Auth::discover_ms_public_keys();
            if($keys == NULL) {

                Logger::write_log("ERROR", "Could not retrieve public keys from Microsoft");
                return false;

            }

            // Find the tenant specific public key used to encode JWT token
            $key = Auth::retrieve_ms_public_key($header->kid, $keys);
            if($key == false) {

                Logger::write_log("ERROR", "Could not find expected key in keys retrieved from Microsoft");
                return false;

            }

            // Decode and return the id_token
            return $jwt_decoder::decode(
                $id_token, 
                "-----BEGIN CERTIFICATE-----\n" . wordwrap($key, 64, "\n", true). "\n-----END CERTIFICATE-----",
                array($header->alg)
            );

        }

        /**
         * Discovers the public keys Microsoft used to encode the id_token
         *
         * @since   1.0
         *
         * @return  void 
         */
        private static function discover_ms_public_keys() {

            $ms_keys_url = "https://login.microsoftonline.com/common/discovery/keys";
            $curl = curl_init();

            curl_setopt($curl, CURLOPT_URL, $ms_keys_url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

            if(isset($GLOBALS["wpo365_options"]["skip_host_verification"])
                && $GLOBALS["wpo365_options"]["skip_host_verification"] == 1) {

                    Logger::write_log("DEBUG", "Skipping SSL peer and host verification");

                    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); 
                    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0); 

            }

            Logger::write_log("DEBUG", "Getting current public keys from MSFT");
            $result = curl_exec($curl); // result holds the keys
            if(curl_error($curl)) {
                
                // TODO handle error
                Logger::write_log("ERROR", "error occured whilst getting a token: " . curl_error($curl));
                return NULL;

            }
            
            curl_close($curl);
            return json_decode($result);
        }
    
        /**
         * Retrieves the (previously discovered) public keys Microsoft used to encode the id_token
         *
         * @since   1.0
         *
         * @param   string  key-id to retrieve the matching keys
         * @param   array   keys previously discovered
         * @return  void 
         */
        private static function retrieve_ms_public_key($kid, $keys) {

            foreach($keys as $key) {

                if($key[0]->kid == $kid) {

                    if(is_array($key[0]->x5c)) {
                        return $key[0]->x5c[0];
                    }
                    else {
                        return $key[0]->x5c;
                    }
                }
            }
            return false;
        }

        /**
         * Parses url the user should be redirected to upon successful logon
         *
         * @since   1.0
         *
         * @param   string  url => redirect_to parameter set by Wordpress
         * @return  string  redirect_to or site url 
         */
        private static function get_redirect_to($url) {

            // Return base url if argument is missing
            if(empty($url)) {
                return get_site_url();
            }

            $query_string = explode("?", $url);
            parse_str($query_string, $out);
            
            if(isset($out["redirect_to"])) {
                Logger::write_log("DEBUG", "Redirect URL found and parsed: " . $out["redirect_to"]);
                return $out["redirect_to"];
            }

            return get_site_url();
        }

        /**
         * Gets the server relative url
         *
         * @since   1.0
         *
         * @param   string  url the user w
         * @return  string  server relative url 
         */
        private static function get_site_path() {
            $url = get_site_url();
            $segments = explode("/", $url);
            $result = "";
            for($i = 3; $i < count($segments); $i++) {
                $result .= "/" . $segments[$i];
            }
            return $result;
        }

        
    }
?>