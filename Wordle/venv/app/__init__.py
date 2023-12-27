from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from .routes import main as main_routes
from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()
bcrypt = Bcrypt(app)

def create_app():
    app.config.from_pyfile('settings.py')

    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    app.config['SECRET_KEY'] = 'your_secret_key'

    from .routes import main as main_routes
    app.register_blueprint(main_routes)

    return app