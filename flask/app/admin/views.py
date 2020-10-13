from .. import app
from ..models import User, Message, Token, db
from .forms import LoginForm

from flask import render_template, redirect, url_for, flash

from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

from flask_login import LoginManager, login_user, login_required, logout_user, current_user

class AdminViewModels(ModelView):
    
    column_display_pk = True

    def is_accessible(self):
        if current_user.is_authenticated:
            if User.isAdmin(current_user.username):
                return True
        else:
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

class AdminViewIndex(AdminIndexView):
    def is_accessible(self):
        if current_user.is_authenticated:
            if User.isAdmin(current_user.username):
                return True
        else:
            flash('U are not admin :)')
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

admin = Admin(app, "Mail", index_view=AdminViewIndex(), endpoint='admin')
admin.add_view(AdminViewModels(User, db.session))
admin.add_view(AdminViewModels(Message, db.session))
admin.add_view(AdminViewModels(Token, db.session))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods = ['GET', 'POST'])
def index():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.get_user_by_username(login_form.username.data)
        if user and User.verify_hash(login_form.password.data, user.password):
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            flash('Login failed')
    return render_template('index.html', form = login_form)

@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for('index'))
    return redirect(url_for('index'))