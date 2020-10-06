from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

app = Flask(__name__)
api = Api(app)
jwt = JWTManager(app)

app.config.from_pyfile('config.py')
app.app_context().push()

from . import views, resources
from .models import db, Token

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
api.add_resource(resources.AdminFunc, '/api/admin')