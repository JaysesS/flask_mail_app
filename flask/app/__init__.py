from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

app = Flask(__name__, template_folder = 'admin/templates')
api = Api(app)
jwt = JWTManager(app)

app.config.from_pyfile('config.py')
app.app_context().push()

from . import resources
from .models import db, Token
from .admin import views

db.init_app(app)
db.create_all()

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return Token.is_jti_blacklisted(jti)

api.add_resource(resources.UserRegister, '/api/registration')
api.add_resource(resources.UserLogin, '/api/login')
api.add_resource(resources.TokenRefresh, '/api/token/refresh')
api.add_resource(resources.UserLogoutAccess, '/api/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/api/logout/refresh')
api.add_resource(resources.Messages, '/api/mail')
api.add_resource(resources.AdminMessages, '/api/admin/mail')
api.add_resource(resources.AdminUserControl, '/api/admin/user')