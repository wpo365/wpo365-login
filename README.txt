=== Wordpress + Office 365 login ===
Contributors: wpo365
Donate link: https://www.wpo365.com
Tags: office 365, azure active directory, authentication, login, oauth, microsoft
Requires at least: 4.8.1
Tested up to: 4.8.1
Stable tag: 1.5
Requires PHP: 5.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Description ==

WordPress + Office 365 login allows Microsoft O365 users to seemlessly and securely log on to your corporate WordPress intranet: No username or password required!

= Plugin Features =

- Automatically log on users that have successfully authenticated with Azure Active Directory / Office 365
- Create a new WordPress user for each Office 365 user (and match both users by email address)
- Allow for both WordPress-only and Office 365 users to log on to your corporate intranet
- Prevent Office 365 users to change their email address
- Prevent Office 365 users to request a new password
- Refresh authentication when its expired (by default after one hour)

= Prerequisites =

- We have tested our plugin with Wordpress 4.8.1 and PHP 5.5.0 and 5.6.25
- You need to be (Office 365) Tenant Administrator to configure both Azure Active Directory and the plugin
- [Redux Framework Plugin](https://de.wordpress.org/plugins/redux-framework/) to configure the Plugin’s option (a warning will be shown upon plugin activation)
- You may want to consider further restrict access to the otherwise publicly available wp-content directory

= Support =

We will go to great length trying to support you if the plugin doesn't work as expected. You can create new issues over at [Github](https://github.com/wpo365/wpo365-login/issues). We haven't been able to test our plugin in all endless possible Wordpress configurations and versions but we are keen to hear from you.

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