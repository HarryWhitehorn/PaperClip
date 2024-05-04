from flask import Flask
import dotenv
import os

from udp import logger

from .models import *

dotenv.load_dotenv()
PRUNE_TIME = int(os.environ.get("PRUNE_TIME"))

def create_app():
    app = Flask(__name__)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY").encode()
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI") #'mysql://root:root@db:3306/paperclip'

    db.init_app(app)
    
    with app.app_context():
        db.create_all()

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app