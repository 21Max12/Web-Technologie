from flask import Flask
from .extensions import db, bcrypt, login_manager
from .sockets import socketio
from .routes import main as main_routes
from. models import User, Game, Gamewords, init_gamewords



def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db' # Pfad zur Datenbank
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


    db.init_app(app)

    with app.app_context():
        db.create_all()
        init_gamewords()

    bcrypt.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app, logger=True, engineio_logger =True)
    

    from .routes import main as main_routes
    app.register_blueprint(main_routes)

    return app

