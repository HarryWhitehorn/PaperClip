import os

import dotenv
from flask import Flask

from udp import logger  # noqa: F401

from .models import *

dotenv.load_dotenv()
PRUNE_TIME = int(os.environ.get("PRUNE_TIME"))


def create_app():
    app = Flask(__name__)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY").encode()
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI")

    db.init_app(app)

    with app.app_context():
        db.create_all()

    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    return app
