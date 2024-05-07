import os

import dotenv
from flask import Flask

from udp import logger  # noqa: F401

from .models import *  # noqa: F403

from sqlalchemy_utils import database_exists, create_database

dotenv.load_dotenv()
PRUNE_TIME = int(os.environ.get("PRUNE_TIME"))


def create_app():
    app = Flask(__name__)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY").encode()
    uri = os.environ.get("SQLALCHEMY_DATABASE_URI")
    _init = False
    if not database_exists(uri):
        _init = True
        create_database(uri)
    app.config["SQLALCHEMY_DATABASE_URI"] = uri

    db.init_app(app)  # noqa: F405

    with app.app_context():
        db.create_all()  # noqa: F405
        
    if _init:
        with app.app_context():
            # init games
            from rps import ID, NAME, MIN_PLAYERS, MAX_PLAYERS
            Statement.createGame(ID, NAME, MIN_PLAYERS, MAX_PLAYERS)  # noqa: F405
            # example accounts
            m = Statement.createAccount("Mario", "ItsAMe123")  # noqa: F405
            p = Statement.createAccount("Peach", "MammaMia!")  # noqa: F405
            b = Statement.createAccount("Bowser", "M4r10SucK5")  # noqa: F405
            Statement.createFriends(m.id, p.id)  # noqa: F405
            Statement.createFriends(p.id, b.id)  # noqa: F405

    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    return app
