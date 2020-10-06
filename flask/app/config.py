import os

if os.environ.get('APP_STAGE') is None:
    # Local 
    user = "jayse"
    passwd = "1337"
    database = "email_db"
    host = "127.0.0.1"
    port = "3306"
elif os.environ.get('APP_STAGE') == "PROD":
    # Server
    user = os.environ.get('APP_DB_USER')
    passwd = os.environ.get('APP_DB_PASSWORD')
    database = os.environ.get('APP_DB_NAME')
    host = os.environ.get('APP_DB_HOST')
    port = os.environ.get('APP_DB_PORT')

SECRET_KEY = 'mysecretkeyforemail'
JWT_SECRET_KEY = 'mysecretjwtkeyforemail'
JWT_BLACKLIST_ENABLED = True
JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{user}:{passwd}@{host}:{port}/{database}'