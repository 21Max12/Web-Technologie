from flask import request, session
from .models import Game
from flask_socketio import SocketIO,emit, join_room, leave_room, send
from .extensions import db
from flask_login import current_user
from .utils import get_user_id_from_sid, wort_uebereinstimmung
from .shared import rooms, user_sid_map

socketio = SocketIO()

@socketio.on('submit_guess')
def handle_guess(data):
    try:
        
        guess = data['guess']
        game_code = data['code']
        sender_sid = request.sid 

        user_id = get_user_id_from_sid(sender_sid)
        
        game = Game.query.filter_by(game_code=game_code).first()

        if game:
            target_word = game.target_word
            ergebnis = wort_uebereinstimmung(target_word, guess)
            emit('guess_result', {'ergebnis': ergebnis, 'sender_sid': sender_sid, 'game_code' : game_code}, broadcast=True)  
            if ergebnis == [1, 1, 1, 1, 1]:
                game.winner = user_id
                db.session.commit()

        else:
            emit('error', {'message': 'No target word set'}, broadcast=True)
    except:
        print("fehler")


@socketio.on('request_target_word')
def handle_request_target_word(data):
    game_code = data['code']
    game = Game.query.filter_by(game_code=game_code).first()
    target_word = game.target_word
    
    if target_word:
        emit('receive_target_word', {'target_word': target_word}, broadcast=True)

@socketio.on("connect")
def connect(auth):
    print('Client Connected')
    room = session.get("room")
    name = session.get("name")

    user_id = current_user.id
    sender_sid = request.sid
    user_sid_map[sender_sid] = user_id

    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": name, "message" : "has entered the room"}, to=room)
    rooms[room]["members"] +=1
    print(f"{name} joined room{room}")


@socketio.on('disconnect')
def disconnect():
    print("Client Disconnected")
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -=1
        if rooms[room]["members"] <=0:
            del rooms[room]
    send({"name": name, "message" : "has left the room"}, to=room)
    print(f"{name} left the room{room}")