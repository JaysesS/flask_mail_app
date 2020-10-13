from flask_restful import Resource, reqparse
from .models import User, Token, Message
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt

authparser = reqparse.RequestParser()
authparser.add_argument('username', help = 'Username required', required = True)
authparser.add_argument('password', help = 'Password required', required = True)

postmail = reqparse.RequestParser()
postmail.add_argument('receiver', help = 'Receiver required', required = True)
postmail.add_argument('text', help = 'Text required', required = True)

getmail = reqparse.RequestParser()
getmail.add_argument('count', help = 'Count required, int value or all', required = True)

adminmail = reqparse.RequestParser()
adminmail.add_argument('count', help = 'Count required, int value or all', required = True)
adminmail.add_argument('filter', help = 'Filter working with username!')

adminstats = reqparse.RequestParser()
adminstats.add_argument('filter', help = 'Filter working with username!')

class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        user = get_jwt_identity()
        access_token = create_access_token(identity = user)
        return {'access_token': access_token}

class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = Token(jti = jti)
            revoked_token.add()
            return {'msg': 'Access token has been revoked'}
        except:
            return {'msg': 'Something went wrong'}, 500

class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = Token(jti = jti)
            revoked_token.add()
            return {'msg': 'Refresh token has been revoked'}
        except:
            return {'msg': 'Something went wrong'}, 500

class UserRegister(Resource):
    def post(self):
        data = authparser.parse_args()
        if User.get_user_by_username(data['username']):
            return {
                    'status': False, 
                    'msg' : 'User already exist'
                   }, 500
        new_user = User(username = data['username'], password = data['password'])
        try:
            new_user.save()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                    'status': True, 
                    'msg' : 'User {} created'.format(data['username']),
                    'access_token': access_token,
                    'refresh_token': refresh_token
                   }
        except Exception as e:
            print(e)
            return {
                    'status': False, 
                    'msg' : 'Something error'
                   }, 500

class UserLogin(Resource):
    def post(self):
        data = authparser.parse_args()
        user = User.get_user_by_username(data['username'])
        if not user:
            return {
                    'status': False, 
                    'msg' : 'User {} not found'.format(data['username'])
                   }, 500

        if User.verify_hash(data['password'], user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                    'status': True, 
                    'msg' : 'Login for {} success'.format(data['username']),
                    'access_token': access_token,
                    'refresh_token': refresh_token
                   }
        else:
            return {
                    'status': False, 
                    'msg' : 'Invalid password'.format(data['username'])
                   }, 500

class Messages(Resource):
    @jwt_required
    def get(self):
        data = getmail.parse_args()
        if data['count'] == 'all':
            messages = Message.get_all_for_username(get_jwt_identity())
            response = {"status": True}
            response["messages"] = [{"receiver": message.receiver, "text": message.text, "date" : message.time} for message in messages]
            return response
        try:
            count = int(data['count'])
            if count < 1:
                raise ValueError
            messages = Message.get_all_for_username(get_jwt_identity())
            if len(messages) < count:
                return {
                        'status': False, 
                        'msg' : 'Count bigger than count messages',
                       }, 500 
            messages = messages[count * -1:]
            response = {"status": True}
            response["messages"] = [{"receiver": message.receiver, "text": message.text, "date" : message.time} for message in messages]
            return response
        except ValueError:
            return {
                    'status': False, 
                    'msg' : 'Check count value',
                   }, 500
    
    @jwt_required
    def post(self):
        data = postmail.parse_args()
        if not User.get_user_by_username(data['receiver']):
            return {
                    'status': False, 
                    'msg' : 'User {} not found'.format(data['receiver']),
                   }, 500

        author = User.get_user_by_username(get_jwt_identity())
        if data['receiver'] == author.username:
            return {
                    'status': False, 
                    'msg' : '{} you can\'t send a message to yourself!'.format(author.username),
                   }, 500
        
        new_message = Message(receiver = data['receiver'], text = data['text'], owner = author)
        new_message.save()
        return {
                'status': True, 
                'msg' : 'Your message send to {}!'.format(data['receiver']),
               }

class AdminMessages(Resource):
    @jwt_required
    def get(self):
        if User.isAdmin(get_jwt_identity()) is False:
            return {
                    'status': False, 
                    'msg' : '{} you are not admin :c'.format(get_jwt_identity()),
                   }, 500
        data = adminmail.parse_args()
        if data['count'] == 'all':
            if data['filter']:
                messages = Message.get_all_for_username(data['filter'])
            else:
                messages = Message.get_all()
            response = {"status": True}
            response["messages"] = [{"author": message.author, "receiver": message.receiver, "text": message.text, "date" : message.time} for message in messages]
            return response
        count = int(data['count'])
        if count < 1:
            return {
                'status': False, 
                'msg' : 'Check count value',
                }, 500
        if data['filter']:
            messages = Message.get_all_for_username(data['filter'])
        else:
            messages = Message.get_all()
        if len(messages) < count:
            return {
                    'status': False, 
                    'msg' : 'Count bigger than count messages',
                    }, 500 
        messages = messages[count * -1:]
        response = {"status": True}
        response["messages"] = [{"receiver": message.receiver, "text": message.text, "date" : message.time} for message in messages]
        return response

class AdminStats(Resource):
    @jwt_required
    def get(self):
        if User.isAdmin(get_jwt_identity()) is False:
            return {
                    'status': False, 
                    'msg' : '{} you are not admin :c'.format(get_jwt_identity()),
                   }, 500
        data = adminstats.parse_args()
        response = {"status": True}
        usernames = User.get_usernames()
        response['users_count'] = len(usernames)
        if data['filter']:
            response['messages_count'] = User.get_count_messages_by_username(data['filter'])
        else:
            response['stats'] = [{'username' : user, "messages_count": User.get_count_messages_by_username(user)} for user in usernames]
        return response