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

namespace Causal\CslOauth2\Storage;

use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Simple PDO storage for TYPO3.
 *
 * @category    Storage
 * @package     csl_oauth2
 * @author      Xavier Perseguers <xavier@causal.ch>
 * @copyright   Causal Sàrl
 * @license     http://www.gnu.org/copyleft/gpl.html
 */
class Typo3Pdo extends \OAuth2\Storage\Pdo {

    /**
     * Typo3Pdo constructor.
     */
    public function __construct()
    {
        
    
        $connection = GeneralUtility::makeInstance(\TYPO3\CMS\Core\Database\ConnectionPool::class)->getConnectionForTable('tx_csloauth2_oauth_clients');
        //$pdo = $connection->getWrappedConnection();
        
        //if (!$pdo instanceof \PDO) {
    
            $config = $GLOBALS['TYPO3_CONF_VARS']['DB']['Connections']['Default'];
            $dsn = 'mysql:dbname=' . $config['dbname'] . ';';
            if ( !empty($config['socket']) ) {
                $dsn .= 'unix_socket=' . $config['socket'];
            } else {
                $dsn .= 'host=' . $config['host'];
                if ( !empty($config['port']) ) {
                    $dsn .= ';port=' . (int)$config['port'];
                }
            }
            $pdo = [
                'dsn' => $dsn,
                'username' => $config['user'],
                'password' => $config['password'],
            ];
        //}
        parent::__construct($pdo, [
            'client_table' => 'tx_csloauth2_oauth_clients',
            'access_token_table' => 'tx_csloauth2_oauth_access_tokens',
            'refresh_token_table' => 'tx_csloauth2_oauth_refresh_tokens',
            'code_table' => 'tx_csloauth2_oauth_authorization_codes',
            'user_table' => 'tx_csloauth2_oauth_users',
            'jwt_table'  => 'tx_csloauth2_oauth_jwt',
            //'jti_table'  => 'oauth_jti',
            'scope_table'  => 'tx_csloauth2_oauth_scopes',
            //'public_key_table'  => 'oauth_public_keys',
        ]);
    }

}
