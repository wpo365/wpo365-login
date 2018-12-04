<?php

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    if ( !class_exists( 'Redux' ) ) {
        return;
    }

    // This is your option name where all the Redux data is stored.
    $opt_name = 'wpo365_options';

    /**
     * ---> SET ARGUMENTS
     * All the possible arguments for Redux.
     * For full documentation on arguments, please refer to: https://github.com/ReduxFramework/ReduxFramework/wiki/Arguments
     * */

    $args = array(
        // TYPICAL -> Change these values as you need/desire
        'opt_name'             => $opt_name,
        // This is where your data is stored in the database and also becomes your global variable name.
        'display_name'         => 'Wordpress + Office 365 - login',
        // Name that appears at the top of your panel
        'display_version'      => '6.1',
        // Version that appears at the top of your panel
        'menu_type'            => 'menu',
        //Specify if the admin menu should appear or not. Options: menu or submenu (Under appearance only)
        'allow_sub_menu'       => true,
        // Show the sections below the admin menu item or not
        'menu_title'           => __( 'WPO365 Options', 'wpo-365-options' ),
        'page_title'           => __( 'WPO365 Options', 'wpo-365-options' ),
        // You will need to generate a Google API key to use this feature.
        // Please visit: https://developers.google.com/fonts/docs/developer_api#Auth
        'google_api_key'       => '',
        // Set it you want google fonts to update weekly. A google_api_key value is required.
        'google_update_weekly' => false,
        // Must be defined to add google fonts to the typography module
        'async_typography'     => true,
        // Use a asynchronous font on the front end or font string
        //'disable_google_fonts_link' => true,                    // Disable this in case you want to create your own google fonts loader
        'admin_bar'            => true,
        // Show the panel pages on the admin bar
        'admin_bar_icon'       => 'dashicons-portfolio',
        // Choose an icon for the admin bar menu
        'admin_bar_priority'   => 50,
        // Choose an priority for the admin bar menu
        'global_variable'      => '',
        // Set a different name for your global variable other than the opt_name
        'dev_mode'             => false,
        // Show the time the page took to load, etc
        'update_notice'        => true,
        // If dev_mode is enabled, will notify developer of updated versions available in the GitHub Repo
        'customizer'           => true,
        // Enable basic customizer support
        //'open_expanded'     => true,                    // Allow you to start the panel in an expanded way initially.
        //'disable_save_warn' => true,                    // Disable the save warning when a user changes a field

        // OPTIONAL -> Give you extra features
        'page_priority'        => null,
        // Order where the menu appears in the admin area. If there is any conflict, something will not show. Warning.
        'page_parent'          => 'themes.php',
        // For a full list of options, visit: http://codex.wordpress.org/Function_Reference/add_submenu_page#Parameters
        'page_permissions'     => 'manage_options',
        // Permissions needed to access the options panel.
        'menu_icon'            => '',
        // Specify a custom URL to an icon
        'last_tab'             => '',
        // Force your panel to always open to a specific tab (by id)
        'page_icon'            => 'icon-themes',
        // Icon displayed in the admin panel next to your menu_title
        'page_slug'            => 'wpo365-options',
        // Page slug used to denote the panel
        'save_defaults'        => true,
        // On load save the defaults to DB before user clicks save or not
        'default_show'         => false,
        // If true, shows the default value next to each field that is not the default value.
        'default_mark'         => '',
        // What to print by the field's title if the value shown is default. Suggested: *
        'show_import_export'   => true,
        // Shows the Import/Export panel when not used as a field.

        // CAREFUL -> These options are for advanced use only
        'transient_time'       => 60 * MINUTE_IN_SECONDS,
        'output'               => true,
        // Global shut-off for dynamic CSS output by the framework. Will also disable google fonts output
        'output_tag'           => true,
        // Allows dynamic CSS to be generated for customizer and google fonts, but stops the dynamic CSS from going to the head
        // 'footer_credit'     => '',                   // Disable the footer credit of Redux. Please leave if you can help it.

        // FUTURE -> Not in use yet, but reserved or partially implemented. Use at your own risk.
        'database'             => '',
        // possible: options, theme_mods, theme_mods_expanded, transient. Not fully functional, warning!

        'use_cdn'              => true,
        // If you prefer not to use the CDN for Select2, Ace Editor, and others, you may download the Redux Vendor Support plugin yourself and run locally or embed it in your code.

        //'compiler'             => true,
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-features',
        'href'  => 'https://www.wpo365.com/wpo365-login-features-and-authentication-flow/',
        'title' => __( 'Features', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-premium-features',
        'href'  => 'https://www.wpo365.com/downloads/wordpress-office-365-login-premium/',
        'title' => __( 'More Features', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-installation',
        'href'  => 'https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/',
        'title' => __( 'Installation', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-settings',
        'href'  => 'https://www.wpo365.com/wpo365-options-explained/',
        'title' => __( 'Options', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-troubleshooting',
        'href'  => 'https://www.wpo365.com/troubleshooting-the-wpo365-login-plugin/',
        'title' => __( 'Troubleshooting', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-support',
        'href'  => 'https://www.wpo365.com/how-to-get-support/',
        'title' => __(  'Support', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-mu-installation',
        'href'  => 'https://www.wpo365.com/version-3-0-supports-wordpress-multisite-wpmu/',
        'title' => __( 'Wordpress multisite', 'wpo-365-options' ),
    );

    $args['share_icons'][] = array(
        'url'   => 'https://twitter.com/WPO365',
        'title' => 'Follow us on Twitter',
        'icon'  => 'el el-twitter'
    );
    
    $args['share_icons'][] = array(
        'url'   => 'https://github.com/wpo365/wpo365-login/',
        'title' => 'Visit us on GitHub',
        'icon'  => 'el el-github'
        //'img'   => '', // You can use icon OR img. IMG needs to be a full URL.
    );

    // Add content after the form.
    // $args['intro_text'] = __( '<p>This text is displayed above the options panel. It isn\'t required, but more info is always better! The intro_text field accepts all HTML.</p>', 'wpo-365-options' );
    // $args['footer_text'] = __( '<p>This text is displayed below the options panel. It isn\'t required, but more info is always better! The footer_text field accepts all HTML.</p>', 'wpo-365-options' ); */

    Redux::setArgs($opt_name, $args );

    // -> START Basic Fields
    Redux::setSection($opt_name, array(
        'title'    => __( 'Azure AD', 'wpo-365-options' ),
        'id'       => 'aad_config',
        'desc'     => __( 'Consult the following <a href="https://www.wpo365.com/wpo365-options-explained#AzureAdOptions">online documentation</a> for a detailed explanation of the Azure AD configuration options.', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'custom_domain',
                'type'     => 'text',
                'title'    => __( 'Your (own) domain', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/your-own-domain/"><strong>help</strong></a>]',
                'desc'     => __( 'The domain you (optionally) added in Microsoft 365 e.g. mycompany.com', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'Only fill out if you added a custom domain e.g. mycompany.com to your Office 365 account. Do not add the cloud-only yourcompany.onmicrosoft.com domain here.',
                )
            ),
            array(
                'id'       => 'default_domain',
                'type'     => 'text',
                'title'    => __( 'Default domain', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/default-domain/"><strong>help</strong></a>]',
                'desc'     => __( 'Your default (cloud-only) O365 domain e.g. mycompany.onmicrosoft.com', 'wpo-365-options' ),
            ),
            array(
                'id'       => 'use_v2',
                'type'     => 'checkbox',
                'title'    => __( 'Use Azure AD v2.0 endpoint', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/azure-ad-v2/"><strong>help</strong></a>]',
                'desc'     => __( 'The updated v2.0 implementation of the authorization model (preview)', 'wpo-365-options' ),
                'default'  => '0',
                'hint'     => array(
                    'content' => 'Only switch to v2.0 if know what you are doing and/or you want to benefit from the possibility to allow users from any AD tenant and/or MSA accounts to register.',
                )
            ),
            array(
                'id'       => 'application_id',
                'type'     => 'text',
                'title'    => __( 'AAD Application ID', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/azure-ad-application-id/"><strong>help</strong></a>]',
                'desc'     => __( 'The Application Id assigned to your app when you registered it with Azure AD', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'You can find this in the Azure Portal. Click Azure Active Directory, click App Registrations, choose the application and locate the Application Id on the application page.',
                )
           ),
           array(
                'id'       => 'tenant_id',
                'type'     => 'text',
                'title'    => __( 'AAD Tenant ID', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/azure-ad-tenant-id/"><strong>help</strong></a>]',
                'desc'     => __( 'Azure Active Directory Identifier', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'The {tenant} value in the path of the request can be used to control who can sign into the application. The allowed values are tenant identifiers, for example, 8eaef023-2b34-4da1-9baa-8bc8c9d6a490 or contoso.onmicrosoft.com or common for tenant-independent tokens.',
                )
            ),
            array(
                'id'       => 'aad_resource_uri',
                'type'     => 'text',
                'title'    => __( 'Default resource ID', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/default-resource-id/"><strong>help</strong></a>]',
                'desc'     => __( 'The application will by default request access to Windows Azure Active Directory to sign in and read profile data if you leave this field unchanged', 'wpo-365-options' ),
                'default'     => '00000002-0000-0000-c000-000000000000'
            ),
            array(
                'id'       => 'application_secret',
                'type'     => 'text',
                'title'    => __( 'Application Secret', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/application-secret/"><strong>help</strong></a>]',
                'desc'     => __( 'ONLY USED FOR ADVANCED INTEGRATION SCENARIOS - The (AAD) Application secret you created as part of the Azure Active Directory configuration', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                //'hint'     => array(
                //    'content' => 'You can find this in the Azure Portal. Click Azure Active Directory, click App Registrations, choose the application and locate the Application ID URI on the application page.',
                //)
            ),
            array(
                'id'       => 'redirect_url',
                'type'     => 'text',
                'title'    => __( 'Redirect URI', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/redirect-uri/"><strong>help</strong></a>]',
                'desc'     => __( 'The redirect_uri of your app (for Wordpress default setup, append a slash at the end e.g. https://www.intra.net/wp-admin/ (click "?" for important information when your hoster offers advanced caching services)', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'A valid address within your website where Microsoft will send the authentication response. It must exactly match one of the redirect_uris you registered for your app in the Azure AD portal. If your WordPress sits behind a proxy that also does caching or if you using caching plugins you must use https://www.your-website.com/wp-admin/ to make sure the page that receives the request is not served from the cache.',
                )
            ),
            array(
                'id'       => 'nonce_secret',
                'type'     => 'text',
                'title'    => __( 'Nonce secret', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/nonce-secret/"><strong>help</strong></a>]',
                'desc'     => __( 'A nonce is a number used once and is used to test the integrity of requests sent to Microsoft' ),
                'default'  => 'YOUR_NONCE_SECRET',
            ),
            array(
                'id'       => 'pages_blacklist',
                'type'     => 'textarea',
                'title'    => __( 'Pages Blacklist', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/pages-blacklist/"><strong>help</strong></a>]',
                'desc'     => __( 'Semi colon separated list of page file names', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'Page file names listed here will be excluded from session validation.',
                ),
                'default'     => 'wp-login.php;wp-cron.php;admin-ajax.php'
            ),
            array(
                'id'       => 'domain_whitelist',
                'type'     => 'textarea',
                'title'    => __( 'Domain whitelist', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/domain-whitelist-wordpress-multisite/"><strong>help</strong></a>]',
                'desc'     => __( 'Semi colon separated list of domain names', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'Only users with (SMTP) domains listed here will be allowed to sign on. This is only useful, when configuring the plugin to use a multi-tenant Azure AD application registration. If you have no idea, what this is about, then leaving this field empty is your best option.',
                ),
            ),
            array(
                'id'       => 'session_duration',
                'type'     => 'text',
                'title'    => __( 'Duration of a session', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/duration-of-a-session/"><strong>help</strong></a>]',
                'desc'     => __( 'Duration in seconds until a user\'s session expires and the user needs to re-authenticate (default one hour)' ),
                'default'  => '3600',
            ),
        )
    ) );

    Redux::setSection($opt_name, array(
        'title'    => __( 'User Management', 'wpo-365-options' ),
        'id'       => 'usrmgmt_config',
        'desc'     => __( 'Consult the following <a href="https://www.wpo365.com/wpo365-options-explained#UserManagement">online documentation</a> for a detailed explanation of the User Management configuration options.', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'block_email_change',
                'type'     => 'checkbox',
                'title'    => __( 'User cannot change email address' ) . ' [<a target="_blank" href="https://www.wpo365.com/user-cannot-change-email-address/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Intercepts a user trying to change his or her email address and reverts that action', 'wpo-365-options' ),
                'default'  => '1',
            ),
            array(
                'id'       => 'block_password_change',
                'type'     => 'checkbox',
                'title'    => __( 'User cannot change password' ) . ' [<a target="_blank" href="https://www.wpo365.com/user-cannot-change-password/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Prevents a user who is not an administrator from changing his or her password', 'wpo-365-options' ),
                'default'  => '1',
            ),
            array(
                'id'       => 'auth_scenario',
                'type'     => 'select',
                'title'    => __( 'Authentication scenario', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/authentication-scenario/"><strong>help</strong></a>]',
                'subtitle' => __( 'Select \'Intranet\' to secure both Wordpress front- and backend and \'Internet\' to secure only the backend with WPO365-login.', 'wpo-365-options' ),
                //'desc'     => __( 'This is the description field, again good for additional info.', 'redux-framework-demo' ),
                'options'  => array(
                    '1' => 'Intranet',
                    '2' => 'Internet'
                ),
                'default'  => '1'
            ),
            array(
                'id'       => 'create_and_add_users',
                'type'     => 'checkbox',
                'title'    => __( 'Create new users', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/create-new-users/"><strong>help</strong></a>]',
                'desc'     => __( 'Automatically create a Wordpress user' ),
                'hint'     => array(
                    'content' => __( 'When checked the plugin will try and find an existing Wordpress user given the user\'s email address and if not found create a new user. In case of Wordpress Multisite the user will also be added to the site he/she tried to access. If unchecked the user with a given email address must already be (manually) created prior to that user logging in.', 'wpo-365-options' ),
                ),
                'default'  => '1'
            ),
            array(
                'id'       => 'new_usr_default_role',
                'type'     => 'text',
                'title'    => __( 'Default role main site', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/default-role-main-site/"><strong>help</strong></a>]',
                'desc'     => __( 'Role assigned in the main when creating a new Wordpress user to match an Office 365 user' ),
                'default'  => 'subscriber',
                'hint'     => array(
                    'content' => 'In case of a multisite Wordpress installation the user is added to the main site and to the site he/she is requesting access to. This settings is for the default role in the main site.',
                )
            ),
            array(
                'id'       => 'mu_new_usr_default_role',
                'type'     => 'text',
                'title'    => __( 'Default role sub site', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/default-role-sub-site/"><strong>help</strong></a>]',
                'desc'     => __( 'ONLY USED FOR MULTISITE INSTALLATIONS - Role assigned in a subsite when creating a new Wordpress user to match an Office 365 user' ),
                'default'  => 'author',
                'hint'     => array(
                    'content' => 'In case of a multisite Wordpress installation the user is added to the main site and to the site he/she is requesting access to. This settings is for the default role in the latter site.',
                )
            )
        )
    ) );

    Redux::setSection($opt_name, array(
        'title'  => __( 'Integration', 'wpo-365-options' ),
        'id'     => 'integration_config',
        'desc'   => __( 'Consult the following <a href="https://www.wpo365.com/wpo365-options-explained#integration">online documentation</a> for a detailed explanation of the Integration configuration options.', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'enable_token_service',
                'type'     => 'checkbox',
                'title'    => __( 'Enable token service' ) . ' [<a target="_blank" href="https://www.wpo365.com/bearer-token-service/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Enables the plugin\'s builtin AJAX service that can be consumed by client side (JavaScript) apps to retrieve Azure AD bearer tokens e.g. for SharePoint Online and Microsoft Graph.', 'wpo-365-options' ),
                'default'  => '0',
            ),
            array(
                'id'       => 'enable_nonce_check',
                'type'     => 'checkbox',
                'title'    => __( 'Check nonce' ) . ' [<a target="_blank" href="https://www.wpo365.com/check-nonce/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'When checked, the request sent to the AJAX server must include a nonce. See <a target="_blank" href="https://www.wpo365.com/check-nonce/"><strong>online documentation</strong></a> for instructions.', 'wpo-365-options' ),
                'default'  => '0',
            ),
        )
    ) );

    Redux::setSection($opt_name, array(
        'title'  => __( 'Errors', 'wpo-365-options' ),
        'id'     => 'error_config',
        'desc'   => __( 'Consult the following <a href="https://www.wpo365.com/wpo365-options-explained#errors">online documentation</a> for a detailed explanation of the Integration configuration options.', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'WPO_ERROR_NOT_CONFIGURED',
                'type'     => 'textarea',
                'title'    => 'NOT_CONFIGURED' . ' [<a target="_blank" href="https://www.wpo365.com/custom-errors/"><strong>help</strong></a>]',
                'default'  => 'Wordpress + Office 365 login not configured yet. Please contact your System Administrator.',
            ),
            array(
                'id'       => 'WPO_ERROR_CHECK_LOG',
                'type'     => 'textarea',
                'title'    => 'CHECK_LOG' . ' [<a target="_blank" href="https://www.wpo365.com/custom-errors/"><strong>help</strong></a>]',
                'default'  => 'Please contact your System Administrator and check log file.',
            ),
            array(
                'id'       => 'WPO_ERROR_TAMPERED_WITH',
                'type'     => 'textarea',
                'title'    => 'TAMPERED_WITH' . ' [<a target="_blank" href="https://www.wpo365.com/custom-errors/"><strong>help</strong></a>]',
                'default'  => 'Your login might be tampered with. Please contact your System Administrator.',
            ),
            array(
                'id'       => 'WPO_ERROR_USER_NOT_FOUND',
                'type'     => 'textarea',
                'title'    => 'USER_NOT_FOUND' . ' [<a target="_blank" href="https://www.wpo365.com/custom-errors/"><strong>help</strong></a>]',
                'default'  => 'Could not create or retrieve your login. Please contact your System Administrator.',
            ),
            array(
                'id'       => 'WPO_ERROR_NOT_IN_GROUP',
                'type'     => 'textarea',
                'title'    => 'NOT_IN_GROUP' . ' [<a target="_blank" href="https://www.wpo365.com/custom-errors/"><strong>help</strong></a>]',
                'default'  => 'Access Denied. Please contact your System Administrator.',
            ),
        )
    ) );

    Redux::setSection($opt_name, array(
        'title'  => __( 'Miscellaneaous', 'wpo-365-options' ),
        'id'     => 'misc_config',
        'desc'   => __( 'Consult the following <a href="https://www.wpo365.com/wpo365-options-explained#Miscellaneous">online documentation</a> for a detailed explanation of the Miscellaneous configuration options.', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'debug_mode',
                'type'     => 'checkbox',
                'title'    => __( 'Enable debug mode' ) . ' [<a target="_blank" href="https://www.wpo365.com/enable-debug-mode/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Enable debug mode so the plugin will output verbose information to the Wordpress debug.log file', 'wpo-365-options' ),
                'default'  => '0',
            ),
            array(
                'id'       => 'skip_host_verification',
                'type'     => 'checkbox',
                'title'    => __( 'Skip SSL host verification' ) . ' [<a target="_blank" href="https://www.wpo365.com/skip-ssl-host-verification/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Enable SSL host verification to improve overall security and you are sure the required server-side dependencies for CURL to verify an SSL host are installed', 'wpo-365-options' ),
                'default'  => '1',
            ),
            array(
                'id'       => 'debug_log_id_token',
                'type'     => 'checkbox',
                'title'    => __( 'Log id token' ) . ' [<a target="_blank" href="https://www.wpo365.com/log-id-token/"><strong>help</strong></a>]',
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'When enabled the plugin will write the id token into the Wordpress log file when debug logging is enabled', 'wpo-365-options' ),
                'default'  => '0',
            ),
            array(
                'id'       => 'leeway',
                'type'     => 'text',
                'title'    => __( 'Leeway time', 'wpo-365-options' ) . ' [<a target="_blank" href="https://www.wpo365.com/leeway-time/"><strong>help</strong></a>]',
                'desc'     => __( 'Extra (leeway) time in seconds to account for clock skew when checking the id token validity', 'wpo-365-options' ),
                'default'  => '300',
            ),
        )
    ) );