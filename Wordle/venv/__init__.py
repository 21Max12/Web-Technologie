from flask import Flask
from .extensions import db, bcrypt, socketio, login_manager
from .routes import main as main_routes

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db' # Pfad zur Datenbank
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    from . import models

    from .routes import main as main_routes
    app.register_blueprint(main_routes)

    return app

