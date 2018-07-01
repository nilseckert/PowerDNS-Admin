import os
basedir = os.path.abspath(os.path.dirname(__file__))

# BASIC APP CONFIG
WTF_CSRF_ENABLED = os.getenv('WTF_CSRF_ENABLED', True) == 'True'
SECRET_KEY = os.getenv('SECRET_KEY', 'We are the world')
BIND_ADDRESS = os.getenv('BIND_ADDRESS', '127.0.0.1')
PORT = os.getenv('PORT', 9191)
LOGIN_TITLE = os.getenv('LOGIN_TITLE', "PDNS")

# TIMEOUT - for large zones
TIMEOUT = os.getenv('TIMEOUT', 10)

# LOG CONFIG
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')

# For Docker, leave empty string
LOG_FILE = os.getenv('LOG_FILE', '')

# Upload
UPLOAD_DIR = os.getenv('UPLOAD_DIR', os.path.join(basedir, 'upload'))

# DATABASE CONFIG
#You'll need MySQL-python
SQLA_DB_TYPE = os.getenv('SQLA_DB_TYPE', 'sqlite')

if SQLA_DB_TYPE == 'sqlite':
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'pdns.db')
elif SQLA_DB_TYPE == 'mysql':
	SQLA_DB_USER = os.getenv('SQLA_DB_USER', 'powerdnsadmin')
	SQLA_DB_PASSWORD = os.getenv('SQLA_DB_PASSWORD', 'powerdnsadminpassword')
	SQLA_DB_HOST = os.getenv('SQLA_DB_HOST', 'mysqlhostorip')
	SQLA_DB_NAME = os.getenv('SQLA_DB_NAME', 'powerdnsadmin')
	SQLALCHEMY_DATABASE_URI = 'mysql://'+SQLA_DB_USER+':'+SQLA_DB_PASSWORD+'@'+SQLA_DB_HOST+'/'+SQLA_DB_NAME


SQLALCHEMY_MIGRATE_REPO = os.getenv('SQLALCHEMY_MIGRATE_REPO', os.path.join(basedir, 'db_repository'))
SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', True) == 'True'

# LDAP CONFIG
LDAP_ENABLED = os.getenv('LDAP_ENABLED', False) == 'True'
LDAP_TYPE = os.getenv('LDAP_TYPE', 'ldap')
LDAP_URI = os.getenv('LDAP_URI', 'ldaps://your-ldap-server:636')
# with LDAP_BIND_TYPE you can specify 'direct' or 'search' to use user credentials
# for binding or a predefined LDAP_USERNAME and LDAP_PASSWORD, binding with non-DN only works with AD
LDAP_BIND_TYPE= 'direct' # direct or search
LDAP_USERNAME = os.getenv('LDAP_USERNAME', 'cn=dnsuser,ou=users,ou=services,dc=duykhanh,dc=me')
LDAP_PASSWORD = os.getenv('LDAP_PASSWORD', 'dnsuser')
LDAP_SEARCH_BASE = os.getenv('LDAP_SEARCH_BASE', 'ou=System Admins,ou=People,dc=duykhanh,dc=me')
LDAP_GROUP_SECURITY = os.getenv('LDAP_GROUP_SECURITY', False) == 'True'
LDAP_ADMIN_GROUP = os.getenv('LDAP_ADMIN_GROUP', 'CN=PowerDNS-Admin Admin,OU=Custom,DC=ivan,DC=local')
LDAP_USER_GROUP = os.getenv('LDAP_USER_GROUP', 'CN=PowerDNS-Admin User,OU=Custom,DC=ivan,DC=local')
# Additional options only if LDAP_TYPE=ldap
LDAP_USERNAMEFIELD = os.getenv('LDAP_USERNAMEFIELD', 'uid')
LDAP_FILTER = os.getenv('LDAP_FILTER', '(objectClass=inetorgperson)')
# enable LDAP_GROUP_SECURITY to allow Admin and User roles based on LDAP groups
#LDAP_GROUP_SECURITY = True # True or False
#LDAP_ADMIN_GROUP = 'CN=DnsAdmins,CN=Users,DC=example,DC=me'
#LDAP_USER_GROUP = 'CN=Domain Admins,CN=Users,DC=example,DC=me'

## AD CONFIG
#LDAP_TYPE = 'ad'
#LDAP_URI = 'ldaps://your-ad-server:636'
#LDAP_USERNAME = 'cn=dnsuser,ou=Users,dc=domain,dc=local'
#LDAP_PASSWORD = 'dnsuser'
#LDAP_SEARCH_BASE = 'dc=domain,dc=local'
## You may prefer 'userPrincipalName' instead
#LDAP_USERNAMEFIELD = 'sAMAccountName'
## AD Group that you would like to have accesss to web app
#LDAP_FILTER = 'memberof=cn=DNS_users,ou=Groups,dc=domain,dc=local'

# Github Oauth
GITHUB_OAUTH_ENABLE = os.getenv('GITHUB_OAUTH_ENABLE', False) == 'True'
GITHUB_OAUTH_KEY = os.getenv('GITHUB_OAUTH_KEY', '')
GITHUB_OAUTH_SECRET = os.getenv('GITHUB_OAUTH_SECRET', '')
GITHUB_OAUTH_SCOPE = os.getenv('GITHUB_OAUTH_SCOPE', 'email')
GITHUB_OAUTH_URL = os.getenv('GITHUB_OAUTH_URL', 'http://127.0.0.1:9191/api/v3/')
GITHUB_OAUTH_TOKEN = os.getenv('GITHUB_OAUTH_TOKEN', 'http://127.0.0.1:9191/oauth/token')
GITHUB_OAUTH_AUTHORIZE = os.getenv('GITHUB_OAUTH_AUTHORIZE', 'http://127.0.0.1:9191/oauth/authorize')


# Google OAuth
GOOGLE_OAUTH_ENABLE = os.getenv('GOOGLE_OAUTH_ENABLE', False) == 'True'
GOOGLE_OAUTH_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID', ' ')
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET', ' ')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', '/user/authorized')
GOOGLE_TOKEN_URL = os.getenv('GOOGLE_TOKEN_URL', 'https://accounts.google.com/o/oauth2/token')
GOOGLE_TOKEN_PARAMS = {
    'scope': 'email profile'
}
GOOGLE_AUTHORIZE_URL = os.getenv('GOOGLE_AUTHORIZE_URL', 'https://accounts.google.com/o/oauth2/auth')
GOOGLE_BASE_URL = os.getenv('GOOGLE_BASE_URL', 'https://www.googleapis.com/oauth2/v1/')

# SAML Authnetication
SAML_ENABLED = os.getenv('SAML_ENABLED', False) == 'True'
SAML_DEBUG = os.getenv('SAML_DEBUG', True) == 'True'
SAML_PATH = os.getenv('SAML_PATH', os.path.join(os.path.dirname(__file__), 'saml'))
##Example for ADFS Metadata-URL
SAML_METADATA_URL = os.getenv('SAML_METADATA_URL', 'https://<hostname>/FederationMetadata/2007-06/FederationMetadata.xml')
#Cache Lifetime in Seconds
SAML_METADATA_CACHE_LIFETIME = os.getenv('SAML_METADATA_CACHE_LIFETIME', 1)
SAML_SP_ENTITY_ID = os.getenv('SAML_SP_ENTITY_ID', 'http://<SAML SP Entity ID>')
SAML_SP_CONTACT_NAME = os.getenv('SAML_SP_CONTACT_NAME', '<contact name>')
SAML_SP_CONTACT_MAIL = os.getenv('SAML_SP_CONTACT_MAIL', '<contact mail>')
#Cofigures if SAML tokens should be encrypted.
#If enabled a new app certificate will be generated on restart
SAML_SIGN_REQUEST = os.getenv('SAML_SIGN_REQUEST', False)
#Use SAML standard logout mechanism retreived from idp metadata
#If configured false don't care about SAML session on logout.
#Logout from PowerDNS-Admin only and keep SAML session authenticated.
SAML_LOGOUT = os.getenv('SAML_LOGOUT', False)
#Configure to redirect to a different url then PowerDNS-Admin login after SAML logout
#for example redirect to google.com after successful saml logout
#SAML_LOGOUT_URL = 'https://google.com'

#Default Auth
BASIC_ENABLED = os.getenv('BASIC_ENABLED', True) == 'True'
SIGNUP_ENABLED = os.getenv('SIGNUP_ENABLED', True) == 'True'

# POWERDNS CONFIG
PDNS_STATS_URL = os.getenv('PDNS_STATS_URL', 'http://172.16.214.131:8081/')
PDNS_API_KEY = os.getenv('PDNS_API_KEY', 'you never know')
PDNS_VERSION = os.getenv('PDNS_VERSION', '4.1.1')

# RECORDS ALLOWED TO EDIT
RECORDS_ALLOW_EDIT = ['SOA', 'A', 'AAAA', 'CAA', 'CNAME', 'MX', 'PTR', 'SPF', 'SRV', 'TXT', 'LOC', 'NS', 'PTR']
FORWARD_RECORDS_ALLOW_EDIT = ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'PTR', 'SPF', 'SRV', 'TXT', 'LOC' 'NS']
REVERSE_RECORDS_ALLOW_EDIT = ['SOA', 'TXT', 'LOC', 'NS', 'PTR']

# ALLOW DNSSEC CHANGES FOR ADMINS ONLY
DNSSEC_ADMINS_ONLY = os.getenv('DNSSEC_ADMINS_ONLY', False) == 'True'

# EXPERIMENTAL FEATURES
PRETTY_IPV6_PTR = os.getenv('PRETTY_IPV6_PTR', False) == 'True'

# Domain updates in background, for big installations
BG_DOMAIN_UPDATES = os.getenv('BG_DOMAIN_UPDATES', False) == 'True'
