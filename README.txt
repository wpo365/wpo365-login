=== Wordpress + Office 365 login ===
Contributors: wpo365
Donate link: https://www.wpo365.com/campaigns/donate/
Tags: office 365, azure active directory, authentication, login, oauth, microsoft
Requires at least: 4.8.1
Tested up to: 4.9
Stable tag: 5.0
Requires PHP: 5.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Description ==

Wordpress + Office 365 login allows Microsoft O365 users to seamlessly and securely log on to your corporate Wordpress intranet: No username or password required. Why you need this, you may wonder. Because this way you can ensure that your corporate content such as news, documents etc. that is normally classified as "Internal" or maybe even "Confidential" is not available to just any pair of curious unauthenticated eyes!

= Plugin Features =

- As a Wordpress Administrator you can choose between two scenarios: 'Intranet' or 'Internet'.
- When the 'Intranet' scenario is selected, our plugin will secure both Wordpress front- and backend and will try to verify whether the user can successfully authenticate him or herself with Microsoft Azure Active Directory. If this is the case the user is granted access to page initially requested or else the user is redirected to the default Wordpress login page.
- On the other hand, when the 'Internet' scenario is selected and the user requests an ordinary (front-end) Wordpress post or page, authentication is omitted. Only when the user requests a page from the backend e.g. /wp-admin the plugin will try and authenticate the user using Azure Active Directory.
- In both scenarios, users will be automatically logged on after they have successfully authenticated with Azure Active Directory / Office 365
- And in case the user does so for the very first time, the plugin will create a corresponding new WordPress user for the first three Office 365 users
- Still, when a user would navigate to the default Wordpress login page, he or she can still log on using a Wordpress-only account. This maybe desirable for System Administrators to log on independently from any subsystem such as Azure Active Directory.
- To keep things save, the plugin will by default prevent Office 365 users to change their email address.
- The plugin will also prevent Office 365 users to request a new password.
- After a certain time - by default 1 hour - the plugin will try and refresh the initial authentication.

= Premium Features =

The [premium version](https://www.wpo365.com/downloads/wordpress-office-365-login-premium/) of the plugin offers all of the above, plus:

- Create and update unlimited Office 365 users
- Support for (granting customers, partners etc. access to your (extranet))[https://www.wpo365.com/wordpress-extranet/] website
- The ability to [quickly rollout new users to WordPress](https://www.wpo365.com/synchronize-users-between-office-365-and-wordpress/) from Active Directory
- [Disable user access to WordPress](https://www.wpo365.com/synchronize-users-between-office-365-and-wordpress/) for users that are disabled in your tenant / domain
- [Log out users from Office 365](https://www.wpo365.com/office-365-logout/) when they log out from your WordPress website
- Enhanced security features e.g. Brute Force Attacks prevention
- Enhances a user’s [WordPress profile with information from Microsoft Graph](https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization/) e.g. office location, job title, mobile and business phone numbers
- Replaces default WordPress avatar for a user with the [Office 365 (O365) profile picture](https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization/) and caches it
- Access Control based on users being a member of either an Office 365 or an Azure AD Security group
- Automated WordPress Role Assignment based on a configurable mapping between Office 365 or Azure AD Security groups and WordPress roles
- Plain wp-config.php configuration (improves the overall performance of your website)
- One support item included

Also have a look at [this post](https://www.wpo365.com/wpo365-login-features-and-authentication-flow/) if you need help to decide whether or not our plugin can help you improve the user experience when user try to gain accessing to your corporate intranet or internet WordPress site.

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

= 4.2 =
* Added extra help links to the Redux Options page for easier installation

== Changelog ==

= 1.0 =
* Initial version submitted to Wordpress.org

= 1.1 =
* Added Wordpress compliant readme.txt

= 1.2 =
* Removed wpo365-redirect.php (and calling wp-load.php)
* Fixed debug level logging, now writing most of the logs when debug mode checked
* Added option to manage pages to blacklist from session validation
* Updated readme.txt

= 1.3 =
* Added redux settings for preventing users changing email and/or password
* Improved error handling with error messages shown on default wp login page
* Improved flow and created hook to handle redirect (for future oauth tokens)
* Renamed namespace Logger to Util
* Obfuscated user's id in session cookie

= 1.4 =
* Remove usage of PHP session on each page load to optimize for PHP caching

= 1.5 =
* Renamed main plugin file to wpo365-login.php
* Tested with PHP 5.5.0
* Fixed issue with array notation to support older PHP version
* Fixed issue with generating certificate string
* Removed redirect hook

= 1.6 =
* To resolve (issue 9)[https://github.com/wpo365/wpo365-login/issues/9] changed flow to earlier test if user is wordpress-only and cancel validation if so

= 1.7 =
* Added option to configure default role for any new Wordpress user (representing the Office 365 / Azure AD user) created by the plugin (default role is Subscriber)
* Added option to configure preferred WPO365-login scenario and allowed by default for two scenarios: 'Intranet' to secure both Wordpress front- and backend and 'Internet' to secure only the backend
* Ensured that upon adding a new Wordpress user this user is returned correctly to main the session validation flow.

= 1.8 =
* To resolve (issue 11 - Can't use function return value in write context)[https://github.com/wpo365/wpo365-login/issues/11]

= 1.9 =
* Resolve issue when empty user data is received from Azure Active Directory
* Added option to work-around missing server-side dependencies for CURL to verify SSL host (lowers general security)

= 1.10 =
* Changed the way the PEM string is being put together from wordwrap to chunk_split
* Changed the incoming algorithm to uppercase
* Added additional logging in case id token decoding fails

= 1.11 =
* Added error check to see if the response from Microsoft contains an error and if yes show this error on the login page

= 1.12 =
* Removed setting the domain for a cookie as this caused an issue with Internet Explorer

= 1.13 =
* Setting cookies for all possible paths (similar to how wp cookies are being set)

= 2.0 =
* Improved security by not storing user id in own cookie but instead use Wordpress user metadata
* Added action hook "wpo365_openid_token_processed" that can be used by other Wordpress extensions to get additional access tokens for pulling data from Office 365 into Wordpress pages
* Change options page name with page slug wpo365-options

= 2.1 =
* Plugin will check whether the id token received contains a valid unique name or upn
* Improved logging that would allow an administrator to write the id token to the Wordpress debug log (should be used carefully as this contains sensitive data)

= 2.2 =
* Enhanced support for users with an MSA account (@live.com or @outlook.com) 

= 2.3 =
* Changed the default resource for authorization from application id to Azure Active Directory allowing for consent being delegated plus added the option to change the default resource id configuratively

= 2.4 =
* Tested with Wordpress 4.9 RC 2
* Added default value for scope

= 2.5 =
* Improved flow in case the plugin is not configured
* Added plugin installation and update tracking
* Updated and refactored code to better follow Wordpress guidelines

= 2.6 =
* Fixed a bug that prevented deleting error messages shown on the login page
* Minor changes to captions and labels

= 2.7 =
* Updated tracking to compare plugin version as string

= 2.8 =
* Fixed global plugin version that collides with multiple wpo365 plugins

= 2.9 =
* Fixed issue with keys retrieved from Microsoft that may prevent a user from logging in successfully

= 3.0 =
* Added support for Wordpress multisite [configuration](https://www.wpo365.com/version-3-0-supports-wordpress-multisite-wpmu/)
* Added configuration for a default role in a sub site
* Added configuration to prevent the automatic creation of new wordpress users 
* Added wp-config setting "WPO365_DEFAULT_USER_ROLE" that optionally can override corresponding redux option to tighten security

= 3.1 =
* Added the option to white-list domains for users that may access your Wordpress site. This is only useful, when configuring the plugin to use in combination with a multi-tenant Azure AD application registration. If you have no idea, what this is about, then leaving this field empty is your best option.

= 3.2 =
* Fixed issue with domain white-list.

= 3.3 =
* Fixed issue with safari and firefox nonce cookie not being persisted on redirect

= 3.4 =
* Fixed issue with login-refresh error causing a "your login might be tampered with" error after an hour

= 3.5 =
* Validation of session now starts as soon as the required settings are loaded to ensure that validation of authentication happens as soon as possible

= 3.6 =
* Fixed issues with loading of Redux dependency in case multiple Redux instance are used within one Wordpress site
* Removed the use of cookies to pass error information between page redirects and by doing so avoid "Cannot modify header information - headers already sent" warnings

= 3.7 =
* Replaced use of array as const to support older PHP versions

= 3.8 =
* Added a "Leeway" setting to account for clock skew when checking the id token validity

= 3.9 =
* Updated algorithm to validate a user's email address
* More accurate help & support links

= 3.10 =
* Replaced the nonce algorithm to avoid too much dependency on current URL (e.g. with or without www)

= 3.11 =
* Replaced array construct to remain compatibel with older PHP versions

= 3.12 =
* Now the plugin decides to prepend https to the state property based on the protocol used for the redirect url. Some WordPress hosters use SLL terminating proxies, causing default WordPress SSL detection to fail. This may cause the plugin to redirect the user after login to the wrong website address starting with http instead of https and this eventually may lead to the user being caught in an infinite authentication loop.
* Simplified the nonce algorithm

= 3.13 =
* Added information banner on wpo365-options page

= 4.0 =
* Added license validation for the Personal Blog (free) version, in order to prevent the creation of more than 3 users (unlimited users can still be created manually).

= 4.1 =
* Fixed "Undefined index page" notice visible on the admin page

= 4.2 =
* Added extra help links to the Redux Options page for easier installation

= 5.0 =
* Moved the JWT class into the Wpo namespace (to avoid class loading issues)
* Added psr-4 type auto class loading
* Code refactoring to allow for tighter integration e.g. with [SharePoint Online Plugin](https://wordpress.org/plugins/wpo365-spo/)