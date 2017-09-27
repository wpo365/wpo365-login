=== Wordpress + Office 365 login ===
Contributors: wpo365
Donate link: https://www.wpo365.com
Tags: office 365, azure active directory, authentication, login, oauth
Requires at least: 4.8.1, PHP
Tested up to: 4.8.1
Stable tag: v1.0
Requires PHP: 5.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

== Description ==

WordPress + Office 365 login allows Microsoft O365 users to seemlessly and securely log on to your corporate WordPress intranet: No username or password required.

Plugin Features

- Automatically log on users that have successfully authenticated with Azure Active Directory / Office 365
- Create a new WordPress user for each Office 365 user automatically (and match both users by email address)
- Allow for both WordPress-only and Office 365 users to log on to your corporate intranet
- Prevent Office 365 users to change their email address
- Prevent Office 365 users to request a new password
- Refresh authentication when its expired (by default after one hour)

Prerequisites

- You need to be (Office 365) Tenant Administrator to configure both Azure Active Directory and the plugin
- Redux Framework Plugin https://de.wordpress.org/plugins/redux-framework/ to configure the Plugin’s option (a warning will be shown upon plugin activation)
- You may want to consider further restrict access to the otherwise publicly available wp-content directory

Support

You are entitled to email support when you have downloaded the plugin through our site. Even when you downloaded our plugin from the official WordPress Plugin Directory, we’d still require you to stop by our download site and obtain your free copy here. This way we are able to keep track of the number of downloads and can verify your request by the email you use to contact us.

Installation

You can read this post https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/ for a simple guidance on how to configure Azure Active Directory and the plugin.
Github / Source code

When you’re a developer and interested in the code you should have a look at our repo over at Github https://github.com/wpo365/wpo365-login.

== Installation ==

The WordPress + Office 365 login plugin uses OpenID Connect and Azure Active Directory to authorize access to your WordPress intranet web application. Hence, to get things working, you first will need to register your WordPress intranet with your Azure Active Directory (Azure AD) tenant. This will give you an Application ID for your application, as well as enable it to receive tokens. We will assume that you have all ready downloaded the plugin from our website or from the WordPress Plugin Directory without activating it.

* Sign in to the Azure Portal
* Choose your Azure AD tenant by clicking on your account in the top right corner of the page.
* In the left hand navigation pane, click on Azure Active Directory.
* Click on App Registrations and click on Add.
* Follow the prompts and create a new application. Now, for your WordPress intranet, provide the Sign-On URL which is the base URL of your app, where users can sign in e.g http://www.intra.net
* Once you’ve completed registration, Azure AD will assign your application a unique client identifier, the Application ID.
* You can pick any name you like.
* Once you registered your app, you need to add to add a reply URL used by Microsoft to post the OpenID Connect tokens to.
* Click Reply URLs
* Enter your reply address as follows: http(s)://[your wordpress host e.g. www.wpo365.com]/wp-content/plugins/wpo365-login/wpo365-redirect.php
* Now continue to the App Registration’s properties panel and keep this open in a separate tab as you’ll need the App ID and other information for the final step of configuring the WordPress + Office 365 – login plugin
* In WordPress Admin Dashboard WPO365 Options
* Fill out each field with the corresponding value found in the Azure Active Directory’s App Registration that you just created. The AAD Tenant ID can be found at the bottom of the Azure Active Directory Properties page where it is called Directory ID.
* You’re done and good to go! Now activate the plugin and read any of the messages that may appear. Amongst other things the plugin requires Redux Framework Plugin to be installed to manage its options.
* Once you have installed the Redux Framework those messages won’t show again and you can ready to test your integration with Office 365. To do so, log off and navigating to your intranet’s landing page (or any other page). The WordPress + Office 365 – login plugin will intercept any request to your intranet and validate it. To do so, users will be redirected to Microsoft’s OpenID Connect endpoint where there identity will be confirmed before being again redirected but this time to the Redirect URL entered when you configured the Azure AD App Registration and the WordPress + Office 365 – login plugin. Upon returning from the OpenID Connect endpoint the plugin will again validate the request and try and read the identity information Microsoft added to the request. It will use it to create a new WordPress user if one cannot be found. To do so the plugin uses the user’s unique the email address and will finally automatically log the user in: No user name or password required!
* You will still be able to navigate to your intranet’s default (WordPress) login page /wp-login and here you can still logon with your WordPress-only account.


== Frequently Asked Questions ==

= What about foo bar? =

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