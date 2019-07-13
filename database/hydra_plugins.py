HYDRA_PLUGINS = ['adam6500', 'asterisk', 'cisco', 'cisco-enable', 'cvs', 'ftp', 'ftps', 'http-form-get',
                 'http-form-post', 'http-get', 'http-head', 'http-post', 'http-proxy', 'https-form-get',
                 'https-form-post', 'https-get', 'https-head', 'https-post', 'http-proxy',
                 'http-proxy', 'http-proxy-urlenum', 'icq', 'imap', 'imaps', 'irc', 'ldap2', 'ldap2s', 'ldap3',
                 'ldap3-crammd5', 'ldap3-digestmd5', 'ldap3-crammd5s', 'ldap3-digestmd5s', 'mssql', 'mysql',
                 'nntporacle-listener', 'oracle-sid', 'pcanywhere', 'pcnfs', 'pop3', 'pop3s', 'postgres', 'rdp',
                 'redis', 'rexec', 'rlogin', 'rpcap', 'rsh', 'rtsp', 's7-300',
                 'sip', 'smb', 'smtp', 'smtps', 'smtp-enum', 'snmp', 'socks5', 'ssh', 'sshkey', 'svn', 'teamspeak',
                 'telnet', 'telnets',
                 'vmauthd', 'vnc', 'xmpp']

PLUGINS_ENCRYPTED = ['ftps', 'https-form-get', 'https-form-post', 'https-get', 'https-head', 'https-post', 'imaps',
               'ldap2s', 'ldap3-crammd5s', 'ldap3-digestmd5s', 'pop3s', 'smtps', 'ssh', 'telnets']

PLUGINS_UNENCRYPTED = [plugin for plugin in HYDRA_PLUGINS if plugin not in PLUGINS_ENCRYPTED]
