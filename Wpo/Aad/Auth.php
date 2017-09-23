<?php
    namespace Wpo\Aad;

    // prevent public access to this script
    defined( 'ABSPATH' ) or die();

    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/User/User_Manager.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Logger/Logger.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Firebase/JWT/JWT.php");

    use \Wpo\User\User_Manager;
    use \Wpo\Logger\Logger;
    use \Firebase\JWT\JWT;
    
    class Auth {

        /**
         * Validates each incoming request to see whether user prior to request
         * was authenicated by Microsoft Office 365 / Azure AD.
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function validate_current_session() {

            Logger::write_log("DEBUG", "Validating session for page " . strtolower(basename($_SERVER['PHP_SELF'])));
            Logger::write_log("DEBUG", "Session: ");
            Logger::write_log("DEBUG", $_SESSION);
            Logger::write_log("DEBUG", "Cookie: ");
            Logger::write_log("DEBUG", $_COOKIE);

            // Is the current page blacklisted and if yes cancel validation
            // In a future version the blacklist could be saved as an option
            if(strtolower(basename($_SERVER['PHP_SELF'])) == "wpo365-redirect.php"
               || strtolower(basename($_SERVER['PHP_SELF'])) == "wp-login.php"
               || strtolower(basename($_SERVER['PHP_SELF'])) == "wp-cron.php"
               || strtolower(basename($_SERVER['PHP_SELF'])) == "admin-ajax.php") {
                Logger::write_log("INFO", "Session validation cancelled for page " . strtolower(basename($_SERVER['PHP_SELF'])));
                return;
            }

            // Don't allow access to the front end when WPO365 is unconfigured
            if((empty($GLOBALS["wpo365_options"]["tenant_id"])
                || empty($GLOBALS["wpo365_options"]["application_id"])
                || empty($GLOBALS["wpo365_options"]["redirect_url"])) 
                && !is_admin()) {
                Logger::write_log("INFO", "WPO365 not configured");
                wp_redirect(wp_login_url());
                exit();
            }

            // Don't continue validation if user is already logged in and is a Wordpress-only user
            if(User_Manager::user_is_o365_user() === false) {
                return;
            }

            // Refresh user's authentication when session not yet validated
            if(!isset($_SESSION["WPO365_WP_USR_ID"])
               || !isset($_SESSION["WPO365_EXPIRY"])) { // no session data found
                Logger::write_log("INFO", "Session data invalid or incomplete found");
                Auth::get_openidconnect_and_oauth_token();
            }

            // Refresh user's authentication when previously validated session has expired
            if(intval($_SESSION["WPO365_EXPIRY"]) <= time()) { // tokens expired
                Auth::destroy_session();
                Auth::get_openidconnect_and_oauth_token();
            }
            
            // Session validated so let's get things started
            $wp_usr = get_user_by("ID", $_SESSION["WPO365_WP_USR_ID"]);
            Logger::write_log("INFO", "User " . $wp_usr->ID . " successfully authenticated");
            
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
            $_SESSION["WPO365_NONCE"] = $nonce;

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

            Logger::write_log("INFO", "Getting fresh id and authorization tokens");
            Logger::write_log("INFO", "Authorization URL: " . $authorizeUrl);

            // Redirect to Microsoft Authorization Endpoint
            wp_redirect($authorizeUrl);
            exit(); // exit after redirect
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
        public static function process_id_token() {

            Logger::write_log("INFO", "Processing an new id token");

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

            // Discover and retrieve the tenant specific public keys
            $keys = Auth::discover_ms_public_keys();
            $key = Auth::retrieve_ms_public_key($header->kid, $keys);
            
            // Decode and return the id_token
            return $jwt_decoder::decode(
                $id_token, 
                "-----BEGIN CERTIFICATE-----\r\n" . $key . "\r\n-----END CERTIFICATE-----",
                [$header->alg]
            );

        }

        /**
         * Destroys any session and authenication artefacts 
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function destroy_session() {
            
                Logger::write_log("INFO", "Destroying session " . strtolower(basename($_SERVER['PHP_SELF'])));
                
                // destroy wpo session adn cookies
                session_unset();
                unset($_COOKIE["WPO365_REFRESH_TOKEN"]);
                setcookie("WPO365_REFRESH_TOKEN", "", -3600, Auth::get_site_path()); // expire in the past
            
                // destroy wordpress session and cookies
                wp_clear_auth_cookie();
                wp_destroy_current_session();  
        }

        /**
         * Same as destroy_session but with redirect to login page
         *
         * @since   1.0
         * @return  void
         */
        public static function goodbye() {
             Auth::destroy_session();
             auth_redirect();
        }

        /**
        * Handles redirect from Microsofts authorization service and tries to detect
        * any wrong doing and if detected redirects wrong-doer to Wordpress login instead
        *
        * @since   1.0
        * @return  void
        */
        public static function handle_redirect() {
            
            Logger::write_log("DEBUG", "Handling redirect from Microsoft");

            // Test if a state property is returned and stop if not
            if(!isset($_POST["state"]) || !isset($_POST["id_token"])) {
                Logger::write_log("ERROR", "No state found which is suspect");
                Auth::goodbye();
            }
        
            $id_token = Auth::process_id_token();
        
            // Handle if token could not be processed or nonce is invalid
            if($id_token === false || $id_token->nonce != $_SESSION["WPO365_NONCE"]) {
                Logger::write_log("ERROR", "id token could not be processed and user will be redirected to default Wordpress login");
                Auth::goodbye();
            }
        
            // Delete the nonce session variable
            unset($_SESSION["WPO365_NONCE"]);
                    
            // Ensure user with the information found in the id_token
            $usr = User_Manager::ensure_user($id_token);
            
            // Handle if user could not be processed
            if($usr === false) {
                Logger::write_log("ERROR", "Could not get or create Wordpress user");
                Auth::goodbye();
            }

            // User could log on and everything seems OK so let's restore his state
            Logger::write_log("INFO", "Redirecting to " . $_POST["state"]);
            wp_redirect($_POST["state"]);
        
            exit(); // Always exit after a redirect
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
            Logger::write_log("INFO", "Getting current public keys from MSFT");
            $result = curl_exec($curl); // result holds the keys
            if(!empty(curl_error($curl))) {
                // TODO handle error
                Logger::write_log("ERROR", "error occured whilst getting a token: " . curl_error($curl));
                exit();
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
                Logger::write_log("INFO", "Redirect URL found and parsed: " . $out["redirect_to"]);
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
            Logger::write_log("DEBUG", $segments);
            $result = "";
            for($i = 3; $i < count($segments); $i++) {
                $result .= "/" . $segments[$i];
            }
            return $result;
        }

        
    }
?>