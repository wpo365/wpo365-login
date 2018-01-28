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
        'display_version'      => '3.4',
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
        'id'    => 'wpo365-installation',
        'href'  => 'https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/',
        'title' => __( 'Installation', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-installation',
        'href'  => 'https://www.wpo365.com/version-3-0-supports-wordpress-multisite-wpmu/',
        'title' => __( 'Wordpress multisite', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-troubleshooting',
        'href'  => 'https://www.wpo365.com/troubleshooting-the-wpo365-login-plugin/',
        'title' => __( 'Troubleshooting', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-settings',
        'href'  => 'https://www.wpo365.com/wpo365-options-explained/',
        'title' => __( 'Options', 'wpo-365-options' ),
    );

    $args['admin_bar_links'][] = array(
        'id'    => 'wpo365-support',
        'href'  => 'https://www.wpo365.com/how-to-get-support/',
        'title' => __(  'Support', 'wpo-365-options' ),
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
        'desc'     => __( 'For Wordpress Multisite these settings will be automatically inherited from the main network site and changes will be overwritten', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'application_name',
                'type'     => 'text',
                'title'    => __( 'AAD Application Name', 'wpo-365-options' ),
                'desc'     => __( 'Name used to register the App in Azure Active Directory', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'Click Azure Active Directory, click App Registrations, choose the application and locate its name.',
                )
           ),
           array(
                'id'       => 'tenant_id',
                'type'     => 'text',
                'title'    => __( 'AAD Tenant ID', 'wpo-365-options' ),
                'desc'     => __( 'Azure Active Directory Identifier', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'The {tenant} value in the path of the request can be used to control who can sign into the application. The allowed values are tenant identifiers, for example, 8eaef023-2b34-4da1-9baa-8bc8c9d6a490 or contoso.onmicrosoft.com or common for tenant-independent tokens.',
                )
            ),
            array(
                'id'       => 'application_id',
                'type'     => 'text',
                'title'    => __( 'AAD Application ID', 'wpo-365-options' ),
                'desc'     => __( 'The Application Id assigned to your app when you registered it with Azure AD', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'You can find this in the Azure Portal. Click Azure Active Directory, click App Registrations, choose the application and locate the Application Id on the application page.',
                )
           ),
           array(
                'id'       => 'aad_resource_uri',
                'type'     => 'text',
                'title'    => __( 'Default resource ID', 'wpo-365-options' ),
                'desc'     => __( 'The application will by default request access to Windows Azure Active Directory to sign in and read profile data if you leave this field unchanged', 'wpo-365-options' ),
                'default'     => '00000002-0000-0000-c000-000000000000'
            ),
            array(
                'id'       => 'application_uri',
                'type'     => 'text',
                'title'    => __( 'AAD Application ID URI', 'wpo-365-options' ),
                'desc'     => __( 'ONLY USED FOR ADVANCED INTEGRATION SCENARIOS - The Application ID URI assigned to your app when you registered it with Azure AD', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'You can find this in the Azure Portal. Click Azure Active Directory, click App Registrations, choose the application and locate the Application ID URI on the application page.',
                )
            ),
            array(
                'id'       => 'application_secret',
                'type'     => 'text',
                'title'    => __( 'Application Secret', 'wpo-365-options' ),
                'desc'     => __( 'ONLY USED FOR ADVANCED INTEGRATION SCENARIOS - The (AAD) Application secret you created as part of the Azure Active Directory configuration', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                //'hint'     => array(
                //    'content' => 'You can find this in the Azure Portal. Click Azure Active Directory, click App Registrations, choose the application and locate the Application ID URI on the application page.',
                //)
            ),
            array(
                'id'       => 'scope',
                'type'     => 'text',
                'title'    => __( 'Scope', 'wpo-365-options' ),
                'desc'     => __( 'A space-separated list of scopes', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'For OpenID Connect, it must include the scope openid, which translates to the \'Sign you in\' permission in the consent UI. You may also include other scopes in this request for requesting consent.',
                ),
                'default'     => 'openid'
           ),
            array(
                'id'       => 'redirect_url',
                'type'     => 'text',
                'title'    => __( 'Redirect URI', 'wpo-365-options' ),
                'desc'     => __( 'The redirect_uri of your app (for Wordpress default setup, append slash at the end e.g. https://yourintranet/ or https://yourintranet/wordpress/)', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'Here authentication responses can be sent and received by your app. It must exactly match one of the redirect_uris you registered in the portal.',
                )
            ),
            array(
                'id'       => 'pages_blacklist',
                'type'     => 'textarea',
                'title'    => __( 'Pages Blacklist', 'wpo-365-options' ),
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
                'title'    => __( 'Domain whitelist', 'wpo-365-options' ),
                'desc'     => __( 'Semi colon separated list of domain names', 'wpo-365-options' ),
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                'hint'     => array(
                    'content' => 'Only users with (SMTP) domains listed here will be allowed to sign on. This is only useful, when configuring the plugin to use a multi-tenant Azure AD application registration. If you have no idea, what this is about, then leaving this field empty is your best option.',
                ),
            ),
            array(
                'id'       => 'session_duration',
                'type'     => 'text',
                'title'    => __( 'Duration of a session', 'wpo-365-options' ),
                'desc'     => __( 'Duration in seconds until a user\'s session expires and the user needs to re-authenticate (default one hour)' ),
                'default'  => '3600',
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                //'hint'     => array(
                //    'content' => 'Here authentication responses can be sent and received by your app. It must exactly match one of the redirect_uris you registered in the portal, except it must be url encoded.',
                //)
            ),
            array(
                'id'       => 'refresh_duration',
                'type'     => 'text',
                'title'    => __( 'Duration before refreshing tokens', 'wpo-365-options' ),
                'desc'     => __( 'Duration in seconds until a user\'s refresh token expires and a new refresh token is required (default one week)' ),
                'default'  => '604800',
                //'subtitle' => __( 'Example subtitle.', 'wpo-365-options' ),
                //'hint'     => array(
                //    'content' => 'Here authentication responses can be sent and received by your app. It must exactly match one of the redirect_uris you registered in the portal, except it must be url encoded.',
                //)
            )

        )
    ) );

    Redux::setSection($opt_name, array(
        'title'    => __( 'User Management', 'wpo-365-options' ),
        'id'       => 'usrmgmt_config',
        'desc'     => __( 'For Wordpress Multisite these settings will be automatically inherited from the main network site and changes will be overwritten', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'block_email_change',
                'type'     => 'checkbox',
                'title'    => __( 'User cannot change email address' ),
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Intercepts a user trying to change his or her email address and reverts that action', 'wpo-365-options' ),
                'default'  => '1',
            ),
            array(
                'id'       => 'block_password_change',
                'type'     => 'checkbox',
                'title'    => __( 'User cannot change password' ),
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Prevents a user who is not an administrator from changing his or her password', 'wpo-365-options' ),
                'default'  => '1',
            ),
            array(
                'id'       => 'auth_scenario',
                'type'     => 'select',
                'title'    => __( 'Authentication scenario', 'wpo-365-options' ),
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
                'title'    => __( 'Create new users', 'wpo-365-options' ),
                'desc'     => __( 'Automatically create a Wordpress user' ),
                'hint'     => array(
                    'content' => __( 'When checked the plugin will try and find an existing Wordpress user given the user\'s email address and if not found create a new user. In case of Wordpress Multisite the user will also be added to the site he/she tried to access. If unchecked the user with a given email address must already be (manually) created prior to that user logging in.', 'wpo-365-options' ),
                ),
                'default'  => '1'
            ),
            array(
                'id'       => 'new_usr_default_role',
                'type'     => 'text',
                'title'    => __( 'Default role main site', 'wpo-365-options' ),
                'desc'     => __( 'Role assigned in the main when creating a new Wordpress user to match an Office 365 user' ),
                'default'  => 'subscriber',
                'hint'     => array(
                    'content' => 'In case of a multisite Wordpress installation the user is added to the main site and to the site he/she is requesting access to. This settings is for the default role in the main site.',
                )
            ),
            array(
                'id'       => 'mu_new_usr_default_role',
                'type'     => 'text',
                'title'    => __( 'Default role sub site', 'wpo-365-options' ),
                'desc'     => __( 'ONLY USED FOR MULTISITE INSTALLATIONS - Role assigned in a subsite when creating a new Wordpress user to match an Office 365 user' ),
                'default'  => 'author',
                'hint'     => array(
                    'content' => 'In case of a multisite Wordpress installation the user is added to the main site and to the site he/she is requesting access to. This settings is for the default role in the latter site.',
                )
            )
        )
    ) );

    Redux::setSection($opt_name, array(
        'title'  => __( 'Miscellaneaous', 'wpo-365-options' ),
        'id'     => 'misc_config',
        'desc'   => __( 'For Wordpress Multisite these settings will be automatically inherited from the main network site and changes will be overwritten', 'wpo-365-options' ),
        //'icon'   => 'el el-home',
        'fields' => array(
            array(
                'id'       => 'debug_mode',
                'type'     => 'checkbox',
                'title'    => __( 'Enable debug mode' ),
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Enable debug mode so the plugin will output verbose information to the Wordpress debug.log file', 'wpo-365-options' ),
                'default'  => '0',
            ),
            array(
                'id'       => 'skip_host_verification',
                'type'     => 'checkbox',
                'title'    => __( 'Skip SSL host verification' ),
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'Enable SSL host verification to improve overall security and you are sure the required server-side dependencies for CURL to verify an SSL host are installed', 'wpo-365-options' ),
                'default'  => '1',
            ),
            array(
                'id'       => 'debug_log_id_token',
                'type'     => 'checkbox',
                'title'    => __( 'Log id token' ),
                'subtitle' => __( '', 'wpo-365-options' ),
                'desc'     => __( 'When enabled the plugin will write the id token into the Wordpress log file when debug logging is enabled', 'wpo-365-options' ),
                'default'  => '0',
            ),
        )
    ) );