Firefox hardening
=================

This is a [user.js][1] configuration file for Mozilla Firefox that's supposed to harden Firefox's settings and make it more secure.

[Pyllyukko/user.js](https://github.com/pyllyukko/user.js) is the main source + [Privacytools](https://privacytools.io). Super simplified with lighter threat model to limit website breakages. All the browser encryption settings have been
copied from Pyllyukko.

# How to use the user.js file

## Installation

### Install for a single profile

Copy `user.js` in your current user profile, or (recommended) to a fresh, newly created Firefox profile directory.

The file should be located at:

| OS                         | Path                                                                                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows 7                  | `%APPDATA%\Mozilla\Firefox\Profiles\XXXXXXXX.your_profile_name\user.js`                                                                       |
| Linux                      | `~/.mozilla/firefox/XXXXXXXX.your_profile_name/user.js`                                                                                       |
| OS X                       | `~/Library/Application Support/Firefox/Profiles/XXXXXXXX.your_profile_name`                                                                   |
| Android                    | `/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name` and see [issue #14](https://github.com/pyllyukko/user.js/issues/14) |
| Sailfish OS + Alien Dalvik | `/opt/alien/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name`                                                           |
| Windows (portable)         | `[firefox directory]\Data\profile\`                                       |

Do note that these settings alter your browser behaviour quite a bit, so it is recommended to either create a completely new [profile][15] for Firefox or backup your existing profile directory before putting the ```user.js``` file in place.

### Install system-wide

Create `local-settings.js` in Firefox installation directory, with the following contents:

```
pref("general.config.obscure_value", 0);
pref("general.config.filename", "mozilla.cfg");
```

This file should be located at:

| OS      | Path                                                         |
| ------- | ------------------------------------------------------------ |
| Windows | `C:\Program Files (x86)\Mozilla Firefox\default\pref\`       |
| Linux   |**This file is not required**                                 |
| OS X    | `/Applications/Firefox.app/Contents/Resources/defaults/pref` |


In `user.js`, Change `user_pref(` to  one of:
 * `pref(` (the value will be used as default value on Firefox profile creation, it can be changed in `about:config`)
 * `lockPref(` (the value will be used as default value on Firefox profile creation, will be locked and can't be changed) in `user.js` or in Firefox's `about:config` or settings.

Copy `user.js` to the Firefox installation directory. The file should be located at:

| OS             | Path                                                       |
| -------------- | ---------------------------------------------------------- |
| Windows        | `C:\Program Files (x86)\Mozilla Firefox\mozilla.cfg`       |
| Linux          | `/etc/firefox/firefox.js`                                  |
| Linux (Debian) | `/etc/firefox-esr/firefox-esr.js`                          |
| OS X           | `/Applications/Firefox.app/Contents/Resources/mozilla.cfg` |

### Updating using git

For any of the above methods, you can keep your browser's `user.js` with the latest version available here: Clone the repository, and create a symoblic link from the appropriate location to the `user.js` file in the repository. Just run `git pull` in the repository when you want to update, then restart Firefox:

````
cd ~/.mozilla/firefox
git clone 'https://github.com/pyllyukko/user.js.git'
cd XXXXXXXX.your_profile_name
ln -s ../user.js/user.js user.js
````

### Verifying

Verify that the settings are effective from [about:support](http://kb.mozillazine.org/Troubleshooting_Information_report#Modified_Preferences) (check the "Important Modified Preferences" and "user.js Preferences" sections).


This is not enough!
-------------------

Here's some other tips how you can further harden Firefox:

* Keep your browser updated! If you check [Firefox's security advisories][10], you'll see that pretty much every new version of Firefox contains some security updates. If you don't keep your browser updated, you've already lost the game.
* Disable all unnecessary extensions and plugins!
* Create different [profiles][15] for different purposes
* Change the Firefox's built-in tracking protection to use the [strict list](https://support.mozilla.org/en-US/kb/tracking-protection-pbm?as=u#w_change-your-block-list)
* Change the timezone for Firefox by using the ```TZ``` environment variable (see [here](https://wiki.archlinux.org/index.php/Firefox_privacy#Change_browser_time_zone)) to reduce it's value in browser fingerprinting
* Completely block unencrypted communications using the `HTTPS Everywhere` toolbar button > `Block all unencrypted requests`. This will break websites where HTTPS is not available.

### Add-ons

Here is a list of the most essential security and privacy enhancing add-ons that you should consider using:

* [Certificate Patrol][4]
  * I recommend setting the 'Store certificates even when in [Private Browsing][8] Mode' to get full benefit out of certpatrol, even though it stores information about the sites you visit
* [HTTPS Everywhere](https://www.eff.org/https-everywhere) and [HTTPS by default](https://addons.mozilla.org/firefox/addon/https-by-default/)
* [NoScript](http://noscript.net/)
* [DuckDuckGo Plus](https://addons.mozilla.org/firefox/addon/duckduckgo-for-firefox/) (instead of Google)
* [No Resource URI Leak](https://addons.mozilla.org/firefox/addon/no-resource-uri-leak/) (see [#163](https://github.com/pyllyukko/user.js/issues/163))
* [Decentraleyes](https://addons.mozilla.org/firefox/addon/decentraleyes/)

#### Tracking protection

Tracking protection is one of the most important technologies that you need. The usual recommendation has been to run the [Ghostery](https://www.ghostery.com/) extension, but as it is made by a [potentially evim(tm) advertising company](https://en.wikipedia.org/wiki/Ghostery#Criticism), some people feel that is not to be trusted. One notable alternative is to use [uBlock](https://github.com/gorhill/uBlock), which can also be found at [Mozilla AMO](https://addons.mozilla.org/firefox/addon/ublock-origin/).

Ghostery is still viable option, but be sure to disable the [GhostRank](https://www.ghostery.com/en/faq#q5-general) feature.

Do note, that this user.js also enables Mozilla's built-in [tracking protection][12], but as that's quite new feature it is to be considered only as a fallback and not a complete solution. As it utilizes [Disconnect's list](https://support.mozilla.org/en-US/kb/tracking-protection-firefox#w_what-is-tracking-protection), recommending Disconnect seems redundant.

So to summarize, pick one between Ghostery and uBlock, depending on your personal preferences.

See also:
* [Mozilla Lightbeam][13] extension
* [Privacy Badger](https://www.eff.org/privacybadger) extension from EFF (also to be considered as an additional security measure and not a complete solution)
* [Web Browser Addons](https://prism-break.org/en/subcategories/gnu-linux-web-browser-addons/) section in [PRISM break](https://prism-break.org/)
* [\[Talk\] Ghostery Vs. Disconnect.me Vs. uBlock #16](https://github.com/pyllyukko/user.js/issues/16)
* [Ghostery sneaks in new promotional messaging system #47](https://github.com/pyllyukko/user.js/issues/47)
* [Are We Private Yet?](http://www.areweprivateyet.com/) site (made by Ghostery)
* [Tracking Protection in Firefox For Privacy and Performance](https://kontaxis.github.io/trackingprotectionfirefox/#papers) paper
* [How Tracking Protection works in Firefox](https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/)

#### Add-ons for mobile platforms

* [NoScript Anywhere](https://noscript.net/nsa/)
* [uBlock](https://addons.mozilla.org/android/addon/ublock-origin/)
* [HTTPS Everywhere](https://www.eff.org/https-everywhere)

Online tests
------------

* [Panopticlick](https://panopticlick.eff.org/)
* [Filldisk](http://www.filldisk.com/)
* [SSL Client Test](https://www.ssllabs.com/ssltest/viewMyClient.html)
* [Evercookie](http://samy.pl/evercookie/)
* [Mozilla Plugin Check][14]
* [BrowserSpy.dk](http://browserspy.dk/)
* [Testing mixed content](https://people.mozilla.org/~tvyas/mixedcontent.html)
  * [Similar from Microsoft](https://ie.microsoft.com/testdrive/browser/mixedcontent/assets/woodgrove.htm)
* [WebRTC stuff](http://mozilla.github.io/webrtc-landing/)
* [Flash Player Version](https://www.adobe.com/software/flash/about/) from Adobe
* [Verify your installed Java Version](https://www.java.com/en/download/installed.jsp)
  * Protip: Don't use Oracle's Java!! But if you really need it, update it regulary!
* [IP Check](http://ip-check.info/?lang=en)
* [Onion test for CORS and WebSocket](http://cure53.de/leak/onion.php)
* [Firefox Addon Detector](http://thehackerblog.com/addon_scanner/)
  * [Blog post](http://thehackerblog.com/dirty-browser-enumeration-tricks-using-chrome-and-about-to-detect-firefox-plugins/)
* [Official WebGL check](http://get.webgl.org/)
* [AudioContext Fingerprint Test Page](https://audiofingerprint.openwpm.com/)
* [battery.js](https://pstadler.sh/battery.js/)
* [Battery API](https://robnyman.github.io/battery/)
* [AmIUnique](https://amiunique.org/) ([Source](https://github.com/DIVERSIFY-project/amiunique))
* itisatrap.org:
  * [Test page for Firefox's built-in Tracking Protection](https://itisatrap.org/firefox/its-a-tracker.html)
  * [Test page for Firefox's built-in Phishing Protection](http://itisatrap.org/firefox/its-a-trap.html) ("Web forgeries")
  * [Test page for Firefox's built-in Malware Protection](http://itisatrap.org/firefox/its-an-attack.html) (attack page)
  * [Test page for Firefox's built-in Malware Protection](http://itisatrap.org/firefox/unwanted.html) (unwanted software)
* [Firefox Resources Reader - BrowserLeaks.com](https://www.browserleaks.com/firefox) (see [#163](https://github.com/pyllyukko/user.js/issues/163))
* [SSL Checker | Symantec CryptoReport](https://cryptoreport.websecurity.symantec.com/checker/views/sslCheck.jsp)

### HTML5test

[HTML5test](http://html5test.com/)

Here's a comparison of the various supported HTML5 features between recent Firefox with these settings, stock Firefox and the Tor Browser:

| Comparison                                                                              | user.js version                          | Firefox version | Firefox baseline | Tor Browser |
| --------------------------------------------------------------------------------------- | ---------------------------------------- | --------------- | ---------------- | ----------- |
| [html5test](https://html5test.com/compare/browser/614ecc2640198302/firefox-35/24a094263fa9f301.html) | 3041fb7204f2547a34083fba7db2009929ed2326 | 36.0.1          | 35               | 4.0.4       |


Known problems
--------------

There are plenty! Hardening your browser will break your interwebs. Here's some examples:

* If you get "TypeError: localStorage is null", you probably need to enable [local storage][3] (``dom.storage.enabled == true``)
* If you get "sec\_error\_ocsp\_invalid\_signing\_cert", it probably means that you don't have the required CA
* If you get "ssl\_error\_unsafe\_negotiation", it means the server is vulnerable to [CVE-2009-3555](http://www.cvedetails.com/cve/CVE-2009-3555) and you need to disable [security.ssl.require\_safe\_negotiation][2] (not enabled currently)
* If you set browser.frames.enabled to false, probably a whole bunch of websites will break
* Some sites require the [referer](https://en.wikipedia.org/wiki/HTTP_referer) header (usually setting ``network.http.sendRefererHeader == 2`` is enough to overcome this and the referer is still "[spoofed][9]")
* The [IndexedDB](https://en.wikipedia.org/wiki/Indexed_Database_API) is something that could potentially be used to track users, but it is also required by some browser add-ons in recent versions of Firefox. It would be best to disable this feature just to be on the safe side, but it is currently enabled, so that add-ons would work. See the following links for further info:
  * [Issue #8](https://github.com/pyllyukko/user.js/issues/8)
  * [IndexedDB Security Review](https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review) (this document also states that "IndexedDB is completely disabled in private browsing mode.", but this should still be verified)
  * [This discussion](http://forums.mozillazine.org/viewtopic.php?p=13842047&sid=041e5edcae225759b7cfffd43fc518d0#p13842047) on mozillaZine Forums
  * [IndexedDB page at MDN](https://developer.mozilla.org/en-US/docs/IndexedDB)
* [Firefox Hello](https://www.mozilla.org/en-US/firefox/hello/) requires [WebRTC](https://en.wikipedia.org/wiki/WebRTC), so you'll need to enable ```media.peerconnection.enabled``` & ```media.getusermedia.screensharing.enabled``` [and apparently](https://github.com/pyllyukko/user.js/issues/9#issuecomment-94526204) disable ```security.OCSP.require```.
* [Captive portals](https://en.wikipedia.org/wiki/Captive_portal) might not let OCSP requests through before authentication, so setting ```security.OCSP.require == false``` might be required before internet access is granted
* [DNT](https://en.wikipedia.org/wiki/Do_Not_Track) is not set, so you need to enable it manually if you want (see the discussion in [issue #11](https://github.com/pyllyukko/user.js/issues/11))
* The ```network.http.referer.spoofSource``` and ```network.http.sendRefererHeader``` settings seems to break the visualization of the 3rd party sites on the [Lightbeam][13] extension
* You can not view or inspect cookies when in private browsing (see https://bugzil.la/823941)
* Installation of ```user.js``` causes saved passwords to be removed from the Firefox (see [#27](https://github.com/pyllyukko/user.js/issues/27))
* Some payment gateways require third-party cookies to be fully enabled before you can make purchases on sites that use them (`network.cookie.cookieBehavior == 0`). Enabling `network.cookie.thirdparty.sessionOnly` will limit their lifetime to the length of the session no matter what.
* On some Android devices, all the pages might be blank (as seen [here](https://github.com/pyllyukko/user.js/pull/136#issuecomment-206812337)) if the setting ```layers.acceleration.disabled``` is set to ```true```. For more information, see [#136](https://github.com/pyllyukko/user.js/pull/136).

The [web console](https://developer.mozilla.org/en-US/docs/Tools/Web_Console) is your friend, **when** websites start to break.
