// Extensions:
// See privacytools.io
// +
// Canvasblocker
// Cors Everywhere
// Country Flag +
// Mouseless

// PREF: Set the default search engine to DuckDuckGo (disabled)
// https://support.mozilla.org/en-US/questions/948134
user_pref("browser.search.defaultenginename",       "DuckDuckGo");
user_pref("browser.search.order.1",             "DuckDuckGo");
user_pref("keyword.URL",                            "https://duckduckgo.com/html/?q=!+");

// PREF: Disable webGL
// https://en.wikipedia.org/wiki/WebGL
// https://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
user_pref("webgl.disabled",                 true);

// PREF: Disable Location-Aware Browsing (geolocation)
// https://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",                    false);

// PREF: Disable WebRTC entirely to prevent leaking internal IP addresses (Firefox < 42)
// NOTICE: Disabling WebRTC breaks peer-to-peer file sharing tools (reep.io ...)
user_pref("media.peerconnection.enabled",           false);

// PREF: Disable "beacon" asynchronous HTTP transfers (used for analytics)
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
user_pref("beacon.enabled",                 false);

// PREF: Disable pinging URIs specified in HTML <a> ping= attributes
// http://kb.mozillazine.org/Browser.send_pings
user_pref("browser.send_pings",                 false);

// PREF: When browser pings are enabled, only allow pinging the same host as the origin page
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
user_pref("browser.send_pings.require_same_host",       true);

// PREF: Disable battery API (Firefox < 52)
// https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
// https://bugzilla.mozilla.org/show_bug.cgi?id=1313580
user_pref("dom.battery.enabled",                false);

// PREF: Enable plugins click-to-play
// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
user_pref("plugins.click_to_play",              true);

// PREF: Enable hardening against various fingerprinting vectors (Tor Uplift project)
// https://wiki.mozilla.org/Security/Tor_Uplift/Tracking
// https://bugzilla.mozilla.org/show_bug.cgi?id=1333933
user_pref("privacy.resistFingerprinting",           true);

// PREF: Disable the built-in PDF viewer
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
// https://blog.mozilla.org/security/2015/08/06/firefox-exploit-found-in-the-wild/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-69/
user_pref("pdfjs.disabled",                 true);

// PREF: Make sure that third-party cookies (if enabled) never persist beyond the session.
// https://feeding.cloud.geek.nz/posts/tweaking-cookies-for-privacy-in-firefox/
// http://kb.mozillazine.org/Network.cookie.thirdparty.sessionOnly
// https://developer.mozilla.org/en-US/docs/Cookies_Preferences_in_Mozilla#network.cookie.thirdparty.sessionOnly
user_pref("network.cookie.thirdparty.sessionOnly",      true);

// PREF: Enable Firefox Tracking Protection
// https://wiki.mozilla.org/Security/Tracking_protection
// https://support.mozilla.org/en-US/kb/tracking-protection-firefox
// https://support.mozilla.org/en-US/kb/tracking-protection-pbm
// https://kontaxis.github.io/trackingprotectionfirefox/
// https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/
user_pref("privacy.trackingprotection.enabled",         true);
user_pref("privacy.trackingprotection.pbmode.enabled",      true);

// PREF: Do not download URLs for the offline cache
// http://kb.mozillazine.org/Browser.cache.offline.enable
user_pref("browser.cache.offline.enable",           false);

// Privacy-tools.io
user_pref("privacy.firstparty.isolate",           true);
user_pref("media.navigator.enabled",                false);  // device status
user_pref("dom.event.clipboardevents.enabled", false);

/// Safer versions of "network.http.referer.spoofSource"
// Send only the scheme, host, and port in the Referer header
user_pref("network.http.referer.trimmingPolicy", 2);
// Only send Referer header when the full hostnames match. (Note: if you notice significant breakage, you might try 1
// combined with an XOriginTrimmingPolicy tweak below.)
user_pref("network.http.referer.XOriginPolicy", 2);
// When sending Referer across origins, only send scheme, host, and port in the Referer header of cross-origin requests.
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

/******************************************************************************
 * SECTION: Cryptography                                                      *
 ******************************************************************************/

// PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
user_pref("network.stricttransportsecurity.preloadlist",    true);

// PREF: Enable Online Certificate Status Protocol
// https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
// https://www.imperialviolet.org/2014/04/19/revchecking.html
// https://www.maikel.pro/blog/current-state-certificate-revocation-crls-ocsp/
// https://wiki.mozilla.org/CA:RevocationPlan
// https://wiki.mozilla.org/CA:ImprovingRevocation
// https://wiki.mozilla.org/CA:OCSP-HardFail
// https://news.netcraft.com/archives/2014/04/24/certificate-revocation-why-browsers-remain-affected-by-heartbleed.html
// https://news.netcraft.com/archives/2013/04/16/certificate-revocation-and-the-performance-of-ocsp.html
// NOTICE: OCSP leaks your IP and domains you visit to the CA when OCSP Stapling is not available on visited host
// NOTICE: OCSP is vulnerable to replay attacks when nonce is not configured on the OCSP responder
// NOTICE: OCSP adds latency (performance)
// NOTICE: Short-lived certificates are not checked for revocation (security.pki.cert_short_lifetime_in_days, default:10)
// CIS Version 1.2.0 October 21st, 2011 2.2.4
user_pref("security.OCSP.enabled",              1);

// PREF: Enable OCSP Stapling support
// https://en.wikipedia.org/wiki/OCSP_stapling
// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
// https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
user_pref("security.ssl.enable_ocsp_stapling",          true);

// PREF: Enable OCSP Must-Staple support (Firefox >= 45)
// https://blog.mozilla.org/security/2015/11/23/improving-revocation-ocsp-must-staple-and-short-lived-certificates/
// https://www.entrust.com/ocsp-must-staple/
// https://github.com/schomery/privacy-settings/issues/40
// NOTICE: Firefox falls back on plain OCSP when must-staple is not configured on the host certificate
user_pref("security.ssl.enable_ocsp_must_staple",       true);

// PREF: Require a valid OCSP response for OCSP enabled certificates
// https://groups.google.com/forum/#!topic/mozilla.dev.security/n1G-N2-HTVA
// Disabling this will make OCSP bypassable by MitM attacks suppressing OCSP responses
// NOTICE: `security.OCSP.require` will make the connection fail when the OCSP responder is unavailable
// NOTICE: `security.OCSP.require` is known to break browsing on some [captive portals](https://en.wikipedia.org/wiki/Captive_portal)
user_pref("security.OCSP.require",              true);

// PREF: Disable TLS Session Tickets
// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzilla.mozilla.org/show_bug.cgi?id=917049
// https://bugzilla.mozilla.org/show_bug.cgi?id=967977
user_pref("security.ssl.disable_session_identifiers",       true);

// PREF: Only allow TLS 1.[0-3]
// http://kb.mozillazine.org/Security.tls.version.*
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min",               1);
user_pref("security.tls.version.max",               4);

// PREF: Disable insecure TLS version fallback
// https://bugzilla.mozilla.org/show_bug.cgi?id=1084025
// https://github.com/pyllyukko/user.js/pull/206#issuecomment-280229645
user_pref("security.tls.version.fallback-limit",        3);

// PREF: Enfore Public Key Pinning
// https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
// "2. Strict. Pinning is always enforced."
user_pref("security.cert_pinning.enforcement_level",        2);

// PREF: Disallow SHA-1
// https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
// https://shattered.io/
user_pref("security.pki.sha1_enforcement_level",        1);

// PREF: Warn the user when server doesn't support RFC 5746 ("safe" renegotiation)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",    true);

// PREF: Disallow connection to servers not supporting safe renegotiation (disabled)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
// TODO: `security.ssl.require_safe_negotiation` is more secure but makes browsing next to impossible (2012-2014-... - `ssl_error_unsafe_negotiation` errors), so is left disabled
//user_pref("security.ssl.require_safe_negotiation",        true);

// PREF: Disable automatic reporting of TLS connection errors
// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
// you can test this at https://pinningtest.appspot.com/
user_pref("security.ssl.errorReporting.automatic",      false);

// PREF: Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
// http://kb.mozillazine.org/Browser.ssl_override_behavior
// https://github.com/pyllyukko/user.js/issues/210
user_pref("browser.ssl_override_behavior",          1);

/******************************************************************************
 * SECTION: Cipher suites                                                     *
 ******************************************************************************/

// PREF: Disable null ciphers
user_pref("security.ssl3.rsa_null_sha",             false);
user_pref("security.ssl3.rsa_null_md5",             false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",           false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",         false);
user_pref("security.ssl3.ecdh_rsa_null_sha",            false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",          false);

// PREF: Disable SEED cipher
// https://en.wikipedia.org/wiki/SEED
user_pref("security.ssl3.rsa_seed_sha",             false);

// PREF: Disable 40/56/128-bit ciphers
// 40-bit ciphers
user_pref("security.ssl3.rsa_rc4_40_md5",           false);
user_pref("security.ssl3.rsa_rc2_40_md5",           false);
// 56-bit ciphers
user_pref("security.ssl3.rsa_1024_rc4_56_sha",          false);
// 128-bit ciphers
user_pref("security.ssl3.rsa_camellia_128_sha",         false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",        false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",      false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",         false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",       false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",     false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",          false);

// PREF: Disable RC4
// https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
// https://bugzilla.mozilla.org/show_bug.cgi?id=1138882
// https://rc4.io/
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2566
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",       false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",         false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",      false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",        false);
user_pref("security.ssl3.rsa_rc4_128_md5",          false);
user_pref("security.ssl3.rsa_rc4_128_sha",          false);
user_pref("security.tls.unrestricted_rc4_fallback",     false);

// PREF: Disable 3DES (effective key size is < 128)
// https://en.wikipedia.org/wiki/3des#Security
// http://en.citizendium.org/wiki/Meet-in-the-middle_attack
// http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
user_pref("security.ssl3.dhe_dss_des_ede3_sha",         false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha",         false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",      false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",        false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",     false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha",       false);
user_pref("security.ssl3.rsa_des_ede3_sha",         false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha",        false);

// PREF: Disable ciphers with ECDH (non-ephemeral)
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",         false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",       false);

// PREF: Disable 256 bits ciphers without PFS
user_pref("security.ssl3.rsa_camellia_256_sha",         false);

// PREF: Enable ciphers with ECDHE and key size > 128bits
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",        true); // 0xc014
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",      true); // 0xc00a

// PREF: Enable GCM ciphers (TLSv1.2 only)
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",   true); // 0xc02b
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",     true); // 0xc02f

// PREF: Enable ChaCha20 and Poly1305 (Firefox >= 47)
// https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
// https://tools.ietf.org/html/rfc7905
// https://bugzilla.mozilla.org/show_bug.cgi?id=917571
// https://bugzilla.mozilla.org/show_bug.cgi?id=1247860
// https://cr.yp.to/chacha.html
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256", true);
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256",   true);

// PREF: Disable ciphers susceptible to the logjam attack
// https://weakdh.org/
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",     false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",          false);

// PREF: Disable ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha",          false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",          false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",     false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",     false);

// PREF: Fallbacks due compatibility reasons
user_pref("security.ssl3.rsa_aes_256_sha",          true); // 0x35
user_pref("security.ssl3.rsa_aes_128_sha",          true); // 0x2f
