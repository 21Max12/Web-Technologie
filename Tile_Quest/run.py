from app import create_app
from app.sockets import socketio

app = create_app()

app.config['DEBUG'] = True

if __name__ == '__main__':
    socketio.run(app)