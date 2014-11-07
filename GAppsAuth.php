<?php
/**
 * GAppsAuth.php -- Allow MediaWiki login with a Google Apps account.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @file
 * @author Kyle Splinter <kyle@lat3ncy.za.net>
 * @ingroup Extensions
 */
if ( !defined( 'MEDIAWIKI' ) ) {
	exit( 1 );
}

define( 'MEDIAWIKI_Gapps_VERSION', '1.0 20141107' );

define('Auth_Yadis_CURL_OVERRIDE', true);

$path = dirname( __FILE__ );

set_include_path( implode( PATH_SEPARATOR, array( $path ) ) . PATH_SEPARATOR . get_include_path() );

/**
 * $wgGAppsDomains string|array of string
 */
$wgGAppsDomains = 'gmail.com';

/**
 * $wgGAppsTempPath string Where to store temporary files.
 */
$wgGAppsTempPath = dirname(realpath(__FILE__)) . DIRECTORY_SEPARATOR . '.tmp';

/**
 * $wgGAppsSessionKey string The name of the session variable.
 */
$wgGAppsSessionKey = 'GAppsUser';

$wgExtensionCredits['other'][] = array(
	'name' => 'GApps Authentication',
	'version' => '1.0',
	'path' => __FILE__,
	'author' => array('Kyle Splinter'),
	'url' => 'https://github.com/kwspl/GAppsWikiAuth',
);
 
$dir = $path . '/';
 
$wgHooks['UserLoadFromSession'][] = 'GAppsAuth::onUserLoadFromSession';
$wgHooks['UserLoginForm'][] = 'GAppsAuth::onUserLoginForm';


class GAppsAuth {
    /** Fill the data of the User object $user from Google Authentication.
     *
     * When the authentication should continue undisturbed after the hook was executed,
     * do not touch $result. When the normal authentication should not happen (e.g.,
     * because $user is completely initialized), set $result to any boolean value.
     * 
     * In any case, return true.
     * 
     * @param $user User Object being loaded.
     * @param $result bool Set to boolean value to abort the normal authentication process
     * 
     * @return bool
     */
    public static function onUserLoadFromSession($user, &$result) {
        global $IP, $wgLanguageCode, $wgRequest, $wgGAppsDomains;
        
        $lang = Language::factory($wgLanguageCode);
        
        if ($wgRequest->getText('title') === $lang->specialPage('Userlogin') 
        && ($wgRequest->getText('gapps_domain') !== '' || is_string($wgGAppsDomains))) {
            require_once("$IP/includes/WebStart.php");

            $domain = is_string($wgGAppsDomains) ? 
                      $wgGAppsDomains : 
                      $wgRequest->getText('gapps_domain');
            
            $gappsUser = self::getGoogleUser($domain);
            $username  = $gappsUser['email'];
            $fullname = $gappsUser['name'];
            
            $user = self::getWikiUser($username, $fullname);
            
            self::returnUserTo();
        } else if ($wgRequest->getText('title') === $lang->specialPage('Userlogout')) {
            $user->logout();
        }
        
        return True;
    }

    /**
     * Redirect user.
     * 
     * @global WebRequest $wgRequest
     * @global OutputPage $wgOut
     */
    public static function returnUserTo() {
        global $wgRequest, $wgOut;

        $returnTo = $wgRequest->getVal("returnto");
        if ($returnTo) {
            $target = Title::newFromText($returnTo);
            if ($target) {
                // Make sure we don't try to redirect to logout !
                if ($target->getNamespace() == NS_SPECIAL)
                    $url = Title::newMainPage()->getFullUrl();
                else
                    $url = $target->getFullUrl();
                
                // Redirect and purge cache
                $wgOut->redirect($url."?action=purge");
            }
        }
    }

    /**
     * Manipulate the login form and display Domain select form.
     * 
     * @param Template $template instance for the form.
     */
    public static function onUserLoginForm(&$template) {
        self::load_libs();
        $template = new GAppsLoginTemplate();
    }

    /**
     * Initialize Google Discovery.
     * 
     * @return mixed Configuration
     */
    public static function init() {
        global $wgRequest, $wgGAppsSessionKey, $wgGAppsTempPath;

        if (!is_null($wgRequest->getSessionData($wgGAppsSessionKey))) {
            return $wgRequest->getSessionData($wgGAppsSessionKey);
        }
        
        if (!file_exists($wgGAppsTempPath)) {
            if (!mkdir($wgGAppsTempPath, 0777, true)) {
                die("GAppsAuth could not create temporary directory \"$wgGAppsTempPath\"");
            }
        }
	if (!is_writable($wgGAppsTempPath)) {
            die("GAppsAuth could not write to \"$wgGAppsTempPath\"");
        }
 
	$config['tmp_path'] = $wgGAppsTempPath;
 
	$config['return_server'] = (isset($_SERVER["HTTPS"]) ? 
                                   'https://' : 
                                   'http://') .$_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'];
	$config['return_url'] = $config['return_server'].$_SERVER['REQUEST_URI'];
 
	// Cache for google discovery
	$config['cache'] = new FileCache($config['tmp_path']);
 
	// Open id lib has many warnig and notices
	error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING ^ E_USER_NOTICE);
        
        return $config;
    }

    /**
     * Process the Google response.
     * 
     * @param mixed $config
     * @return mixed User data array('email', 'name')
     */
    public static function processResponse($config=array()) {
        global $wgRequest, $wgGAppsSessionKey;
        
        $store = new Auth_OpenID_FileStore($config['tmp_path']);
        $consumer = new Auth_OpenID_Consumer($store);
        new GApps_OpenID_Discovery($consumer, null, $config['cache']);
        
        $response = $consumer->complete($config['return_url']);
        
        if ($response->status == Auth_OpenID_CANCEL)
            die('Verification cancelled.');
        if ($response->status == Auth_OpenID_FAILURE)
            die("OpenID authentication failed: " . $response->message);
        if ($response->status != Auth_OpenID_SUCCESS)
            die('Other error');

        $data = array(
            'email' => $wgRequest->getText('openid_ext1_value_email'),
            'name'  => ucfirst($wgRequest->getText('openid_ext1_value_firstname') .
                       ' ' . 
                       ucfirst($wgRequest->getText('openid_ext1_value_lastname'))));
        
        $wgRequest->setSessionData($wgGAppsSessionKey, $data);
 
        return $data;
    }

    /**
     * Redirect user to Google for authentication.
     * 
     * @param mixed $config
     * @param string $domain
     * @return Auth_OpenID_AuthRequest $auth_request An object
     * containing the discovered information will be returned, with a
     * method for building a redirect URL to the server, as described
     * in step 3 of the overview. This object may also be used to add
     * extension arguments to the request, using its 'addExtensionArg'
     * method.
     */
    public static function requestAuth($config=array(), $domain='') {
	$store = new Auth_OpenID_FileStore($config['tmp_path']);
	$consumer = new Auth_OpenID_Consumer($store);
	new GApps_OpenID_Discovery($consumer, null, $config['cache']);
        
        try {
            $auth_request = $consumer->begin($domain);
            if (!is_object($auth_request))
                die('Auth request object error. Try again');
	}
	catch (Exception $error) {
		die($error->getMessage());
	}
        
        return $auth_request;
    }

    /**
     * The information to request from GApps.
     * 
     * @return Auth_OpenID_AX_FetchRequest
     */
    public static function getRequestParameters() {
        $ax = new Auth_OpenID_AX_FetchRequest;
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/email',2,1,'email') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/first',1,1, 'firstname') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/last',1,1, 'lastname') );
 
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/friendly',1,1,'friendly') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson',1,1,'fullname') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/birthDate',1,1,'dob') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/person/gender',1,1,'gender') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/postalCode/home',1,1,'postcode') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/country/home',1,1,'country') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/pref/language',1,1,'language') );
	$ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/pref/timezone',1,1,'timezone') );
        
        return $ax;
    }
    /**
     * Perform Google OpenID Discovery, on success redirect.
     * 
     * @param string $domain
     */
    public static function getGoogleUser($domain) {
        global $wgRequest;
        self::load_libs();
        
        $config = self::init();
        
        if ($wgRequest->getText('janrain_nonce') !== '') {
            return self::processResponse($config);
        }
        
        $auth_request = self::requestAuth($config, $domain);
 
	$auth_request->addExtension(self::getRequestParameters());
        
        // Request URL for auth dialog url
	$redirect_url = $auth_request->redirectURL($config['return_server'], $config['return_url']);
 
	if (Auth_OpenID::isFailure($redirect_url))
		die('Could not redirect to server: ' . $redirect_url->message);
	else
		header('Location: '.$redirect_url);
 
	exit();
    }

    /**
     * Get the WikiMedia user or create if it does not exist.
     * 
     * @param string $email
     * @param string $name
     * @return User
     */
    public static function getWikiUser($email, $name) {
        $user = User::newFromName($email);
        
        // If user does not exist, create.
        if ($user->getID() == 0) {
            $user->addToDatabase();
            $user->setRealName($name);
            $user->setEmail($email);
            $user->setPassword(md5($email));
            $user->setToken();
            $user->saveSettings();
 
            // Update site stats (user count)
            $ssUpdate = new SiteStatsUpdate(0,0,0,0,1);
            $ssUpdate->doUpdate();            
        }
        
        $user->setOption('rememberpassword', 1);
        $user->setCookies();
        
        return $user;
    }

    /**
     * Load libraries required by this extension.
     */
    public static function load_libs() {
        require_once "GAppsLoginTemplate.php";
        
        require_once "Auth/OpenID/Consumer.php";
        require_once "Auth/OpenID/AX.php";
        require_once "Auth/OpenID/google_discovery.php";
        require_once "Auth/OpenID/FileStore.php";
        require_once "Auth/OpenID/SReg.php";
        require_once "Auth/OpenID/PAPE.php";
    }

}

class FileCache {
	var $cache_file;
 
	function __construct($tmp_path) {
		$this->cache_file = $tmp_path.DIRECTORY_SEPARATOR."google.tmp";
	}
 
	function get($name) {
		$cache = unserialize(file_get_contents($this->cache_file));
		return $cache[$name];
	}
 
	function set($name, $value) {
		$cache = unserialize(file_get_contents($this->cache_file));
		$cache[$name] = $value;
		file_put_contents($this->cache_file, serialize($cache));
	}
 
}
