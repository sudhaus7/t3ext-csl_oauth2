<?php
/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with TYPO3 source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

namespace Causal\CslOauth2\Controller;

use Doctrine\DBAL\FetchMode;
use TYPO3\CMS\Core\Crypto\PasswordHashing\InvalidPasswordHashException;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Configuration\BackendConfigurationManager;
use TYPO3\CMS\Extbase\Object\ObjectManager;

class Server
{

    /**
     * @var string
     */
    protected $extKey = 'csl_oauth2';

    /**
     * @var string
     */
    protected $extPath;

    /**
     * @var ObjectManager
     */
    protected $objectManager;

    /**
     * @var BackendConfigurationManager
     */
    protected $configurationManager;

    /**
     * @var \OAuth2\Server
     */
    protected $oauth2Server;

    /**
     * Server constructor.
     */
    public function __construct()
    {
        $this->extPath = \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath($this->extKey);

        $this->objectManager = GeneralUtility::makeInstance(ObjectManager::class);

        $storage = new \Causal\CslOauth2\Storage\Typo3Pdo();
        $this->oauth2Server = new \OAuth2\Server($storage, [
            'allow_implicit' => true,
        ]);

        // Add the "Client Credentials" grant type (it is the simplest of the grant types)
        //$this->oauth2Server->addGrantType(new \OAuth2\GrantType\ClientCredentials($storage));

        // Add the "Authorization Code" grant type (this is where the oauth magic happens)
        $this->oauth2Server->addGrantType(new \OAuth2\GrantType\AuthorizationCode($storage));

        // Add Refreshtoken grant type
        $this->oauth2Server->addGrantType(new \OAuth2\GrantType\RefreshToken($storage));
        
        // Trick when using fcgi, requires this in .htaccess:
        //
        //     RewriteEngine On
        //     RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
        //
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            list($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)));
        }
    }

    /**
     * Handles an authorize request.
     *
     * @return void
     */
    public function handleAuthorizeRequest()
    {
        $request = \OAuth2\Request::createFromGlobals();
        $response = new \OAuth2\Response();

        // Validate the authorize request. if it is invalid, redirect back to the client with the errors in tow
        if (!$this->oauth2Server->validateAuthorizeRequest($request, $response)) {
            $response->send();
            return;
        }

        $clientId = GeneralUtility::_GET('client_id');
        $storage = $this->oauth2Server->getStorage('client');
        $clientData = $storage->getClientDetails($clientId);
        $actionParameters = GeneralUtility::_GET();
        $username = '';
        $messages = [];
        $doLogin = GeneralUtility::_POST('login');

        if ($doLogin) {
            $username = GeneralUtility::_POST('username');
            $password = GeneralUtility::_POST('password');
            if (!(empty($username) || empty($password))) {
                $this->doLogin($clientData['typo3_context'], $username, $password);
            }
        }

        if ($this->isAuthenticated($clientData['client_id'])) {
            $template = 'Authorize.html';
            $actionParameters['mode'] = 'authorizeFormSubmit';
        } else {
            $template = 'Login.html';
            if ($doLogin) {
                // Authentication failed
                $messages[] = [
                    'type' => 'danger',
                    'title' => $this->translate('login.error.title'),
                    'message' => $this->translate('login.error.message'),
                ];
            }
        }

        $actionUrl = GeneralUtility::getIndpEnv('SCRIPT_NAME') . '?' . http_build_query($actionParameters);

        $this->configurationManager = $this->objectManager->get(BackendConfigurationManager::class);
        if (!empty($this->configurationManager)) {
            $typoScriptSetup = $this->configurationManager->getTypoScriptSetup();
            $layoutRootPaths = $typoScriptSetup['plugin.']['csl_oauth2.']['view.']['layoutRootPaths.'];
            $partialRootPaths = $typoScriptSetup['plugin.']['csl_oauth2.']['view.']['partialRootPaths.'];
            $templateRootPaths = $typoScriptSetup['plugin.']['csl_oauth2.']['view.']['templateRootPaths.'];
        }

        if (empty($layoutRootPaths)) {
            $layoutRootPaths = [$this->extPath . 'Resources/Private/Layouts/'];
        }
        if (empty($partialRootPaths)) {
            $partialRootPaths = [$this->extPath . 'Resources/Private/Layouts/'];
        }
        if (empty($templateRootPaths)) {
            $templatePath = $this->extPath . 'Resources/Private/Templates/' . $template;
        } else {
            $templatePath = end($templateRootPaths) . $template;
        }

        // Generate a form to authorize the request
        /** @var \TYPO3\CMS\Fluid\View\StandaloneView $view */
        $view = GeneralUtility::makeInstance(\TYPO3\CMS\Fluid\View\StandaloneView::class);
        $view->setLayoutRootPaths($layoutRootPaths);
        $view->setPartialRootPaths($partialRootPaths);
        $view->setTemplatePathAndFilename($templatePath);

       
        
        
        
        // Initialize localization
        $view->getRequest()->setControllerExtensionName($this->extKey);

        $view->assignMultiple([
            'siteName' => $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename'],
            'client' => $clientData,
            'actionUrl' => $actionUrl,
            'username' => $username,
            'messages' => $messages,
        ]);
    
        $signalSlotDispatcher = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(\TYPO3\CMS\Extbase\SignalSlot\Dispatcher::class);
        list($view, $template) = $signalSlotDispatcher->dispatch(self::class, 'viewPreRender', [$view,$template]);
        $html = $view->render();
        echo $html;
    }

    /**
     * This method is called once the user decides to authorize or cancel the client
     * app's authorization request.
     *
     * @param bool $isAuthorized
     * @param int $userId [Optional] user id
     * @return void
     */
    public function handleAuthorizeFormSubmitRequest($isAuthorized, $userId = null)
    {
        $request = \OAuth2\Request::createFromGlobals();
        $response = new \OAuth2\Response();

        $this->oauth2Server->handleAuthorizeRequest($request, $response, $isAuthorized, $userId)->send();
    }

    
    public function handleProfileRequest($access_token)
    {
        $db = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('tx_csloauth2_oauth_access_tokens');
        $payload = ['error' => 'not found'];
    
        $stmt = $db->select(...['*'])
            ->from('tx_csloauth2_oauth_access_tokens')
            ->where(
                $db->expr()->andX(...[
                    $db->expr()->eq('access_token', $db->quote($access_token)),
                    $db->expr()->gt('expires', 'NOW()')
                ])
            );
        $result = $stmt->execute();
        $access = $result->fetch(\PDO::FETCH_ASSOC);
        if (!empty($access)) {
            $db = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable('fe_users');
            $stmt = $db->select(...[
                'member_id',
                'username',
                'first_name',
                'last_name',
                'email'
            ])
                ->from('fe_users')
                ->where(
                    $db->expr()->andX(...[
                        $db->expr()->eq('uid', $access['user_id']),
                    ])
                );
            $result = $stmt->execute();
            $row = $result->fetch(\PDO::FETCH_ASSOC);
            if (!empty($row)) {
                $row['id'] = $access['user_id'];
                $payload = $row;
                $db->update('fe_users')
                    ->set('lastlogin', time())
                    ->where(...[
                        $db->expr()->andX(...[
                            $db->expr()->eq('uid', $access['user_id']),
                        ])
                    ])->execute();
            }
        }
        
        header('Content-Type: application/json');
        echo \json_encode($payload);
    }
    /**
     * Handles a request for an OAuth2.0 Access Token and sends
     * the response to the client.
     */
    public function handleTokenRequest()
    {
        $request = \OAuth2\Request::createFromGlobals();
        $response = $this->oauth2Server->handleTokenRequest($request);
        if (strpos($response->getParameter('error_description'), 'expired')!==false) {
            $response->setStatusCode(401, 'Unauthorized');
            $response->addHttpHeaders(['WWW-Authenticate'=> sprintf('Bearer realm="%s", error="%s", error_description="%s"', $request->request['client_id'], $response->getParameter('error'), $response->getParameter('error_description'))]);
        }
        $response->send();
    }

    /**
     * Returns true if current user is authenticated for a given OAuth2 client.
     *
     * @param string $clientId
     * @return bool
     */
    public function isAuthenticated($clientId)
    {
        $isAuthenticated = false;

        if ($_SESSION['client_id'] === $clientId) {
            $isAuthenticated = $this->getAuthenticatedUser() > 0;
        }

        return $isAuthenticated;
    }

    /**
     * Returns the authenticated user id.
     *
     * @return int
     */
    public function getAuthenticatedUser()
    {
        return (int)$_SESSION['user_id'];
    }

    /**
     * Translates a label.
     *
     * @param string $id
     * @param array $arguments
     * @return null|string
     */
    protected function translate($id, array $arguments = null)
    {
        $value = \TYPO3\CMS\Extbase\Utility\LocalizationUtility::translate($id, $this->extKey, $arguments);
        return $value !== null ? $value : $id;
    }
    
    /**
     * @param $context
     * @param $username
     * @param $password
     * @throws InvalidPasswordHashException
     */
    protected function doLogin($context, $username, $password)
    {
        // TODO: rely on TYPO3 itself to authenticate

        switch ($context) {
            case 'BE':
                $table = 'be_users';
                break;
            case 'FE':
                $table = 'fe_users';
                break;
            default:
                throw new \InvalidArgumentException('Context "' . $context . '" is not yet implemented', 1459697724);
        }

        $user = null;
        $db = $this->getDatabaseConnection($table);
        $stmt = $db->select(...['uid', 'password'])
            ->from($table)
            ->where(
                $db->expr()->orX(...[
                        $db->expr()->eq('username', $db->quote($username)),
                        $db->expr()->eq('email', $db->quote($username)),
                        $db->expr()->comparison(' CAST('.$db->quoteIdentifier('member_id').' as CHAR) ', $db->expr()::EQ, $db->quote($username)),
                        
                    ])
            );
        $result = $stmt->execute();
        if ($result && $result->rowCount()===1) {
            $user = $result->fetch(\PDO::FETCH_ASSOC);
        }
        
        
    
        if (!empty($user)) {
            $hashedPassword = $user['password'];
    
            $objInstanceSaltedPW = GeneralUtility::makeInstance(\TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory::class)->get($hashedPassword, $context);
            //$objInstanceSaltedPW = \TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory::getSaltingInstance($hashedPassword);
            //$objInstanceSaltedPW = \TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory::getSaltingInstance($hashedPassword);
            if (is_object($objInstanceSaltedPW)) {
                $validPasswd = $objInstanceSaltedPW->checkPassword($password, $hashedPassword);
                if ($validPasswd) {
                    $_SESSION['client_id'] = GeneralUtility::_GET('client_id');
                    $_SESSION['user_id'] = (int)$user['uid'];
                }
            }
            //\TYPO3\CMS\Extbase\Utility\DebuggerUtility::var_dump([$hashedPassword, $context,$objInstanceSaltedPW,$validPasswd]);
        }
    }
    
    /**
     * @param $table
     * @return QueryBuilder
     */
    protected function getDatabaseConnection($table) : QueryBuilder
    {
        return GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($table);
    }
}

$server = new Server();

$mode = GeneralUtility::_GET('mode');
switch ($mode) {
    case 'authorize':
        session_start();
        try {
            $server->handleAuthorizeRequest();
        } catch (InvalidPasswordHashException $e) {
            $content = null;
            $signalSlotDispatcher = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(\TYPO3\CMS\Extbase\SignalSlot\Dispatcher::class);
            list($content) = $signalSlotDispatcher->dispatch(Server::class, 'invalidPasswordHashException', [$content]);
            if ($content === null) {
                throw new InvalidPasswordHashException($e->getMessage(), $e->getCode());
            } else {
                echo $content;
            }
        }
        break;
    case 'authorizeFormSubmit':
        session_start();
        $clientId = GeneralUtility::_GET('client_id');
        $isAuthorized = false;
        $userId = null;

        if ($server->isAuthenticated($clientId)) {
            $userId = $server->getAuthenticatedUser();
            $isAuthorized = (bool)GeneralUtility::_POST('authorize');
        }
        if ($isAuthorized) {
            //\TYPO3\CMS\Extbase\Utility\DebuggerUtility::var_dump([$isAuthorized,$userId,$_SESSION]);
            unset($_SESSION['user_id']);
        }
        $server->handleAuthorizeFormSubmitRequest($isAuthorized, $userId);
        break;
    case 'token':
        $server->handleTokenRequest();
        break;

    case 'profile':
        $access_token = GeneralUtility::_GET('access_token');
        $server->handleProfileRequest($access_token);
        break;
    default:
        throw new \Exception('Invalid mode provided: "' . $mode . '"', 1457023604);
}
