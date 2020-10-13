from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from passlib.hash import pbkdf2_sha256 as sha256

import time

db = SQLAlchemy()

class User(UserMixin, db.Model):

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique = True, nullable = False)
    password = db.Column(db.String(300), nullable = False)
    admin = db.Column(db.Boolean, default = False)
    mails =  db.relationship('Message', backref='owner')

    def __init__(self, username, password):
        self.username = username
        self.password = User.generate_hash(password)

    def __repr__(self):
        return "{}".format(self.username)

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def get_user_by_username(cls, username):
        return cls.query.filter_by(username = username).first()
    
    @classmethod
    def get_usernames(cls):
        return [x.username for x in cls.query.all()]

    @classmethod
    def get_count_messages_by_username(cls, username):
        return len(cls.query.filter_by(username = username).first().mails)

    @classmethod
    def isAdmin(cls, username):
        data = cls.query.filter_by(admin = True).all()
        for user in data:
            if user.username == username:
                return True
        return False

class Message(db.Model):

    __tablename__ = "message"

    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(40), db.ForeignKey('user.username'))
    receiver = db.Column(db.String(40))
    text = db.Column(db.String(1000))
    time = db.Column(db.String(50), default = time.ctime(int(time.time())))

    def save(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def get_all_for_username(cls, username):
        return cls.query.filter_by(author = username).all()
    
    @classmethod
    def get_all(cls):
        return cls.query.all()

class Token(db.Model):

    __tablename__ = "token"

    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)