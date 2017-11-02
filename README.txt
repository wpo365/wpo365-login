=== Wordpress + Office 365 login ===
Contributors: wpo365
Donate link: https://www.wpo365.com
Tags: office 365, azure active directory, authentication, login, oauth, microsoft
Requires at least: 4.8.1
Tested up to: 4.8.1
Stable tag: 2.3
Requires PHP: 5.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Description ==

WordPress + Office 365 login allows Microsoft O365 users to seemlessly and securely log on to your corporate WordPress intranet: No username or password required. Why you need this, you may wonder. Because this way you can ensure that your corporate content such as news, documents etc. that is normally classified as "Internal" or maybe even "Confidential" is not available to just any pair of curious unauthenticated eyes!

= Plugin Features =

- As a Wordpress Administrator you can choose between two scenarios: 'Intranet' or 'Internet'.
- When the 'Intranet' scenario is selected, our plugin will secure both Wordpress front- and backend and will try to verify whether the user can successfully authenticate him or herself with Microsoft Azure Active Directory. If this is the case the user is granted access to page initially requested or else the user is redirected to the default Wordpress login page.
- On the other hand, when the 'Internet' scenario is selected and the user requests an ordinary (front-end) Wordpress post or page, authentication is omitted. Only when the user requests a page from the backend e.g. /wp-admin the plugin will try and authenticate the user using Azure Active Directory.
- In both scenarios, users will be automatically logged on after they have successfully authenticated with Azure Active Directory / Office 365
- And in case the user does so for the very first time, the plugin will create a corresponding new WordPress user (and match both worlds by the user's unique email address)
- Still, when a user would navigate to the default Wordpress login page, he or she can still log on using a Wordpress-only account. This maybe desirable for System Administrators to log on independently from any subsystem such as Azure Active Directory.
- To keep things save, the plugin will by default prevent Office 365 users to change their email address.
- The plugin will also prevent Office 365 users to request a new password.
- After a certain time - by default 1 hour - the plugin will try and refresh the initial authentication.

Also have a look at [this post](https://www.wpo365.com/wpo365-login-features-and-authentication-flow/) if you need help to decide whether or not our plugin can help you improve the user experience when user try to gain accessing to your corporate intranet or internet WordPress site.

= Prerequisites =

- We have tested our plugin with Wordpress 4.8.1 and PHP 5.5.0 and 5.6.25
- You need to be (Office 365) Tenant Administrator to configure both Azure Active Directory and the plugin
- [Redux Framework Plugin](https://de.wordpress.org/plugins/redux-framework/) to configure the Plugin’s option (a warning will be shown upon plugin activation)
- You may want to consider further restrict access to the otherwise publicly available wp-content directory
- A user's browser must support cookies

= Support =

We will go to great length trying to support you if the plugin doesn't work as expected. Go to our [Support Page](https://www.wpo365.com/how-to-get-support/) to get in touch with us. We haven't been able to test our plugin in all endless possible Wordpress configurations and versions so we are keen to hear from you and happy to learn!

= Feedback =

We are keen to hear from you so share your feedback with us at info@wpo365.com and help us get better!

= Open Source =

When you’re a developer and interested in the code you should have a look at our repo over at [(]Github](https://github.com/wpo365/wpo365-login).

== Installation ==

Please refer to [this post](https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/) for detailed installation and configuration instructions.

== Frequently Asked Questions ==

== Screenshots ==

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


