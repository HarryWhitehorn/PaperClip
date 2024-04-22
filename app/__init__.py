from flask import Flask
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

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app