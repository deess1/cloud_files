# -*- coding: utf-8 -*-

# Django settings for Public schedule project
import os
import MySQLdb
import MySQLdb.cursors

DEBUG = False
TEMPLATE_DEBUG = DEBUG

TEST_ENV = False

ADMINS = (
    # ('Your Name', 'email@domain.com'),
)

MANAGERS = ADMINS

WEB_SERVER_URL = 'https://files.domain.com'

ALLOWED_HOSTS = ['files.domain.com']


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'db_name',     
        'USER': 'sql_user', 
        'PASSWORD': 'xxx',
        'HOST': '',    
        'PORT': '3309',
    }
}

TIME_ZONE = 'Europe/Moscow'

LANGUAGE_CODE = 'ru-RU'

DEFAULT_CHARSET = 'utf-8'
SITE_ID = 1
USE_I18N = True
USE_L10N = True

MEDIA_ROOT = ''
MEDIA_URL = ''
STATIC_ROOT = ''
STATIC_URL = '/static/'
ADMIN_MEDIA_PREFIX = '/static/admin/'
SECRET_KEY = ''

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
#    'django.middleware.csrf.CsrfViewMiddleware',
#    'django.contrib.messages.middleware.MessageMiddleware',
 #   'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

SESSION_COOKIE_SECURE = False

ROOT_URLCONF = 'urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'cloud_files',    
)

CLOUD_FILE_DIR = r'/home/files_prod/files'

LOGIN_URL = ''

LOGOUT_URL = ''

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.CallbackFilter',
            'callback': lambda r: True #not DEBUG
        }
    },
    'handlers': {
        'log_file': {
            'level': 'ERROR',
           # 'filters': ['require_debug_false'],
            'class': 'logging.FileHandler',
            'filename': os.path.join('/var', 'log', 'regserver', 'cloud_files.log'),
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['log_file'],
            'level': 'ERROR',
            'propagate': True,
        },
       'error_log': {
            'handlers': ['log_file'],
            'level': 'ERROR',
            'propagate': True,
        }
    }
}

class FraudError(Exception): pass

class SkipReqError(Exception): pass 

# return error http codes:
HTTP_SERVER_ERR = 1
HTTP_REQUEST_ERR = 2
HTTP_FRAUD_ERR = 3
HTTP_NOT_DEFINED_ERR = 10

class HtttpReqError(Exception): 
    code = None 
    def __init__(self, msg, c = HTTP_NOT_DEFINED_ERR):
        self.message = msg
        self.code = c
    
class Context:
    conn = None
    ip = None
    user = None
    use_ie = None
    email = None  
    usage = None
    product = None
    lang = None
    sid = None  # system identifier (computer id)
    pid = None  # program identifier
    check_cnt = None
    client_time = None
    client_date = None
    ver = None
    rid = None  # request identified (client's random)

    
    req_id = None     # requests
    client_id = None  # clients
    
    lic_num = None # license num

    cert_id = None
    
    asw_mindex = None
    req_mindex = None
    asw_cindex = None
        
    fraud_err = None
    module = None
    debug = None
    def __init__(self):
        self.conn = MySQLdb.connect(host=DATABASES['default']['HOST'], user=DATABASES['default']['USER'], passwd=DATABASES['default']['PASSWORD'], db=DATABASES['default']['NAME'], use_unicode = 1, charset = 'utf8', cursorclass=MySQLdb.cursors.DictCursor)
        
    def __del__(self):
        self.conn.close()