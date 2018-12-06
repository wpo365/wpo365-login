=== Wordpress + Office 365 login ===
Contributors: wpo365
Tags: office 365, azure active directory, authentication, login, oauth, microsoft
Requires at least: 4.8.1
Tested up to: 5.0
Stable tag: 6.1
Requires PHP: 5.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Description ==

Wordpress + Office 365 login allows Microsoft O365 users to seamlessly and securely log on to your corporate Wordpress intranet: No username or password required. Why you need this, you may wonder. Because this way you can ensure that your corporate content such as news, documents etc. that is normally classified as "Internal" or maybe even "Confidential" is not available to just any pair of curious unauthenticated eyes!

= Plugin Features =

== User Registration ==

- Register a new WordPress user upon successful authentication [[details | configuration]](https://www.wpo365.com/wpo365-login-features-and-authentication-flow/)
- Enrich a user's WordPress user profile with information from Microsoft Graph e.g. Job Title, Contact Details and Office Location ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization#extra_user_profile_fields)
- Automatically assign WordPress user role(s) based on Azure AD group membership(s) when a user signs into your website ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/role-based-access-using-azure-ad-groups/)
- Replace a user's WordPress avatar with that user's Office 365 profile image ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization#avatar)
- Allow a user from another Office 365 tenant to register ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/wordpress-extranet/)
- Prevent an Office 365 user to change their WordPress password and / or email address [[details | configuration]](https://www.wpo365.com/prevent-update-email-address-and-password/)

== Single Sign-on ==

- Authenticate an employee or student when that user navigates to your (intranet) website [[details | configuration]](https://www.wpo365.com/wpo365-login-features-and-authentication-flow/)
- Authenticate a partner coming from another tenant when that user navigates to your (extranet) website ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/wordpress-extranet/)
- Authenticate an internet editor or administrator when that user navigates to your (corporate) website's backend [[details | configuration]](https://www.wpo365.com/wpo365-login-features-and-authentication-flow/)
- Authenticate a user when that user clicks the "Sign in (with Microsoft)" button or link that you placed on a page with a simple shortcode ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/authentication-shortcode/)
- Accept / reject login attempts based on the user's Azure AD group membership(s) ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/role-based-access-using-azure-ad-groups/)
- Sign out a user from Office 365 when that user signs out of your website ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [details | configuration]](https://www.wpo365.com/office-365-logout/)
- Intercept manual login attempts when the user is an Office 365 user ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/intercept-manual-login/)

== User Synchronization ==

- Quickly enroll new users to WordPress from Azure AD (per user or in batches) ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/synchronize-users-between-office-365-and-wordpress/)
- Update WordPress user profile with information from Microsoft Graph e.g. Job Title, Contact Details and Office Location (per user or in batches) ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization/)
- Update WordPress user role(s) based on Azure AD group membership(s) (per user or in batches) ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/role-based-access-using-azure-ad-groups/)
- See what user WordPress users do not have a matching Office 365 account ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/synchronize-users-between-office-365-and-wordpress/)

== Integration ==

- Client-side solutions can request access tokens for Azure AD secured resources e.g. SharePoint Online and Microsoft Graph ([premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/)) [[details | configuration]](https://www.wpo365.com/pintra-fx/)
- Developers can include a simple and robust API from [npm](https://www.npmjs.com/package/pintra-fx) [[details | configuration]](https://www.wpo365.com/pintra-fx/)
- Authors can inject Pintra Framework apps into any page or post using a simple WordPress shortcode / macro [[details | configuration]](https://www.wpo365.com/pintra-fx/)

Also have a look at [this post](https://www.wpo365.com/wpo365-login-features-and-authentication-flow/) if you need help to decide whether or not our plugin can help you improve the user experience when user try to gain accessing to your corporate intranet or internet WordPress site.

https://youtu.be/fM4TSbNS-R4

= Prerequisites =

- Make sure that you have disabled caching for your Website in case your website is an intranet and access to WP Admin and all pubished pages and posts requires authentication. With caching enabled, the plugin may not work as expected
- We have tested our plugin with Wordpress 4.8.1 and PHP 5.5.0 and 5.6.25
- You need to be (Office 365) Tenant Administrator to configure both Azure Active Directory and the plugin
- [Redux Framework Plugin](https://de.wordpress.org/plugins/redux-framework/) to configure the Plugin’s option (a warning will be shown upon plugin activation)
- You may want to consider further restrict access to the otherwise publicly available wp-content directory
- A user's browser must support cookies

= Support =

We will go to great length trying to support you if the plugin doesn't work as expected. Go to our [Support Page](https://www.wpo365.com/how-to-get-support/) to get in touch with us. We haven't been able to test our plugin in all endless possible Wordpress configurations and versions so we are keen to hear from you and happy to learn!

= Feedback =

We are keen to hear from you so share your feedback with us on [Twitter](https://twitter.com/WPO365) and help us get better!

= Open Source =

When you’re a developer and interested in the code you should have a look at our repo over at [Github](https://github.com/wpo365/wpo365-login).

== Installation ==

Please refer to [this post](https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/) for detailed installation and configuration instructions.

== Frequently Asked Questions ==

== Screenshots ==

== Upgrade Notice ==

When upgrading from version 5.3 to 6.x please make sure to review the following configuration options:

- Azure AD - Your (own) domain
- Azure AD - Default domain
- Integration - Enable token service
- Integration - Check nonce
- Errors - [all]

== Changelog ==

= 6.1 =
* Change: Removed the (Redux) WPO365 Option for scope
* Change: Support for Azure AD v2.0 authentication and access token requests (preview, more information will follow in a separate upcoming post)
* Change: Updated the access token (AJAX) service API to support Azure AD v2.0 scope based token requests
* Change: Authorization, access and refresh codes and tokens are now stored as JSON encoded classes
* Change: Previously deprecated methods have been removed (other / third party plugins and apps must integrate using the API now)

= 6.0 =
* Change: A configuration option has been added to always redirect a user to a designated page upon signin into the website
* Change: A client (side) application can now request an oauth access token for any Azure AD secured resource e.g. Graph and SharePoint Online
* Change: A configuration section has been added to configure / disable the aforementioned AJAX service for Azure AD oauth access tokens
* Change: A Configuration section has been added that allows administrators to define custom login error messages
* Change: Refresh tokens e.g. for Graph and SharePoint Online are now set to expire after 14 days
* Change: The plugin will now cache the Microsoft signin keys used to verify the incoming ID token for 6 hours to improve overall performance
* Change: The flow to obtain access tokens has been refactored and greatly simplied (existing methods have been marked deprecated)
* Fix: Dynamic role assignment will not add default role when user has existing role(s)

= 5.3 =
* Change: Pages Blacklist can now include query string parts e.g. "?api=" but administrators need to be aware that this can potentially weaken overall security [read more](https://www.wpo365.com/pages-blacklist/)

= 5.2 =
* Fix: user_nicename - a WP_User field that is limited to 50 characters - was wrongly set to a user's full name which under circumstances prevented a user from being created successfully

= 5.1 =
* Fix: When searching for O365 users search both in email and login name
* Fix: Check before redirecting whether headers are sent and if yes falls back to an alternative method to redirect
* Fix: search_columns argument for WP_User_Query must be an array

= 5.0 =
* Moved the JWT class into the Wpo namespace (to avoid class loading issues)
* Added psr-4 type auto class loading
* Code refactoring to allow for tighter integration e.g. with [SharePoint Online Plugin](https://wordpress.org/plugins/wpo365-spo/)