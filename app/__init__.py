from flask import Flask, url_for
from flask_login import LoginManager
from .models import *


def create_app():
    app = Flask(__name__)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.config['SECRET_KEY'] = b"MyVerySecretKey"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost:3306/paperclip' #'mysql://root:root@db:3306/paperclip' #

    db.init_app(app)
    
    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    # from .models import Users
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app