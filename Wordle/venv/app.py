from flask import Flask, render_template, request, url_for, redirect, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, SubmitField, validators, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Optional, Email
from datetime import datetime
from flask_bcrypt import Bcrypt
import os
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from string import ascii_uppercase
import random
from functools import wraps
import time



basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        is_user_admin = session.get('is_user_admin')
        print("Aktuelle user_id in der Session:", user_id)
        print("Der Admin status ist", is_user_admin)
        if user_id:
            user = User.query.get(user_id)
            if user and user.is_user_admin:
                return f(*args, **kwargs)
            else:
                flash("Sie haben keine Berechtigung, diese Seite zu sehen.")
        else:
            flash("Sie sind nicht eingeloggt.")
        return redirect(url_for('homescreen'))  
    return decorated_function


@app.route('/admin_view', methods=['GET', 'POST'])
@admin_required
def admin_page():
    return render_template('Admin.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(
         min = 4, max =20)], render_kw = {"placeholder":"Username"})
    
    password = PasswordField(validators = [InputRequired(), Length(
        min = 4, max = 20)], render_kw = {"placeholder": "Password"})
    
    submit = SubmitField("Login")



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(80), nullable = False)
    secure_question = db.Column(db.String(80), nullable = True)
    secure_answer = db.Column(db.String(80), nullable = False)
    e_mail = db.Column(db.String(80), nullable = True)
    is_user_admin = db.Column(db.Boolean, default=False, nullable = False)


class Game(db.Model):
    id_game = db.Column(db.Integer, primary_key=True)
    id_Host = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    id_Join = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    winner = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    target_word = db.Column(db.String(255))
    game_code = db.Column(db.String(255))
    start_time = db.Column(db.Time)



    host = db.relationship('User', foreign_keys=[id_Host], backref=db.backref('hosted_games', lazy=True))
    joiner = db.relationship('User', foreign_keys=[id_Join], backref=db.backref('joined_games', lazy=True))
    winner_user = db.relationship('User', foreign_keys=[winner], backref=db.backref('won_games', lazy=True))

    @property
    def is_full(self):
        return self.id_Host is not None and self.id_Join is not None

class Gamewords(db.Model):
    id_word = db.Column(db.Integer, primary_key = True)
    words = db.Column(db.String)


def add_words(words_):
    for word in words_:
        word_entry = Gamewords(words=word)
        db.session.add(word_entry)

    db.session.commit()


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session['user_id'] = user.id
            session['is_user_admin'] = user.is_user_admin
            session['username'] = user.username
            session['e_mail'] = user.e_mail
            print(user.is_user_admin)
            return redirect(url_for('homescreen'))
        else:
            #raise ValidationError(
                #"Falscher Benutzername oder Kennwort"
                #Benni: Das was ich kommentiert habe ist alt 
            return render_template('Login.html', form=form, error=True)
            
            pass
    return render_template('Login.html', form=form)


@app.route('/homescreen', methods=['GET','POST'])
@login_required
def homescreen():
    is_user_admin = session.get('is_user_admin')
    return render_template('Homescreen.html')

def add_admin():
    raw_password = "Adminspasswort?!_"
    hashed_password = bcrypt.generate_password_hash(raw_password).decode('utf-8')

    raw_secure_answer = "Peter"
    hashed_secure_answer = bcrypt.generate_password_hash(raw_secure_answer).decode('utf-8')

    new_admin = User(
        username="Admin",
        password=hashed_password,
        secure_question="What's the name of your first pet?",
        secure_answer=hashed_secure_answer,
        e_mail="Admin@Admin.de",
        is_user_admin = True
    )
    db.session.add(new_admin)
    db.session.commit()


def delete_users(ids):
    for id in ids:
        user_to_delete = User.query.get(id)
        if user_to_delete:
            db.session.delete(user_to_delete)
    db.session.commit()


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)])
    e_mail = StringField(validators=[Optional(), Email()], render_kw={"placeholder": "E-Mail"})
    security_question = SelectField('Security Question', choices=[('Pet', "What's the name of your first pet?"), ('Car', "What was your first car?"), ('Mother', "What is the mother's surname?")], validators=[InputRequired()])
    security_answer = StringField('Security Answer', validators=[InputRequired()])
    submit = SubmitField("Register")
    
    def validate_confirm_password(self, field):
        if field.data != self.password.data:
            raise ValidationError("Die Passwörter stimmen nicht überein.")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError(
                "Der Username existiert bereits, bitte verwenden einen anderen"
            )

rooms ={}

def generate_unique_code(Length):
    while True:
        code =""
        for _ in range(Length):
            code += random.choice(ascii_uppercase)
        if code not in rooms:
            break
    return code


@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        security_answer = form.security_answer.data
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        secure_question = request.form['security_question']
        hashed_answer = bcrypt.generate_password_hash(security_answer).decode('utf-8')
        e_mail = form.e_mail.data
        
        if User.query.count() == 0:
            is_admin = True
        else:
            is_admin = False

        new_user = User(username=form.username.data, password=hashed_password, secure_question=secure_question, secure_answer=hashed_answer, e_mail=e_mail, is_user_admin=is_admin)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('Register.html', form=form)


@app.route('/pwreset', methods=['GET', 'POST'])
def pwreset():
    if request.method == 'POST':
        return redirect(url_for('newpw'))
    return render_template('PWreset.html')

@app.route('/co_determination_law')
def co_determination_law():
    return render_template('Law.html')

@app.route('/dsgvo')
def dsgvo():
    return render_template('DSGVO.html')

@app.route('/impressum')
def impressum():
    return render_template('Impressum.html')

@app.route('/singleplayer', methods=['POST'])
@login_required
def singleplayer():
    return render_template('Single.html')


@app.route('/multiplayer/<code>', methods=['GET', 'POST'])
@login_required
def multiplayer(code):
    game_id = rooms.get(code)
    print(game_id)

    session_key = f"multiplayer_access_count_{code}"
    if session_key not in session:
        session[session_key] = 0
    session[session_key] += 1

    # Überprüfen, ob das Limit erreicht wurde
    if session[session_key] > 1:
        flash('Sie haben die maximale Anzahl von Aufrufen für dieses Spiel erreicht.')
        return redirect(url_for('homescreen'))

    game_id = rooms.get(code)
    if not game_id:
        flash('Spiel nicht gefunden.')
        return redirect(url_for('homescreen'))  

    logged_in_username = current_user.username
    game = Game.query.get(game_id)
    host_user = User.query.get(game.id_Host)
    join_user = User.query.get(game.id_Join)
    host_name = host_user.username
    join_name = join_user.username
    start_time = game.start_time

    if logged_in_username == join_name:
        player = logged_in_username 
        opponent = host_name
    else:
        player = host_name
        opponent = join_name

    
    if not game or (game.id_Host != current_user.id and (game.id_Join is None or game.id_Join != current_user.id)):
        flash('Sie sind nicht berechtigt, dieses Spiel zu betreten.')
        return redirect(url_for('homescreen'))  
    
    
    return render_template('Multi.html', code=code, player=player, opponent=opponent,start_time=start_time)


def wort_uebereinstimmung(target_word, guess):
    # Initialisierung der Ergebnisliste
    ergebnis = []

    # Um Dopplungen zu vermeiden, wird eine Kopie des Zielwortes erstellt, die bearbeitet wird
    zielwort_kopie = list(target_word)

    # Überprüfung jedes Buchstabens im eingegebenen Wort
    for index, buchstabe in enumerate(guess):
        if index < len(target_word) and buchstabe == target_word[index]:
            # Richtiger Buchstabe an der richtigen Position
            ergebnis.append(1)
            # Markieren des Buchstabens im Zielwort als "verwendet"
            zielwort_kopie[index] = None
        elif buchstabe in zielwort_kopie:
            # Richtiger Buchstabe, aber an der falschen Position
            ergebnis.append(2)
            # Markieren des ersten Vorkommens des Buchstabens im Zielwort als "verwendet"
            zielwort_kopie[zielwort_kopie.index(buchstabe)] = None
        else:
            # Falscher Buchstabe
            ergebnis.append(3)

    return ergebnis


def get_user_id_from_sid(sender_sid):
    return user_sid_map.get(sender_sid)
    

def get_random_gameword():
    count = Gamewords.query.count()
    if count == 0:
        return None  # Keine Wörter in der Datenbank
    random_index = random.randint(0, count - 1)
    random_word = Gamewords.query.offset(random_index).first()
    return random_word.words if random_word else None


@socketio.on('submit_guess')
def handle_guess(data):
    guess = data['guess']
    game_code = data['code']
    sender_sid = request.sid 

    user_id = get_user_id_from_sid(sender_sid)
    
    game = Game.query.filter_by(game_code=game_code).first()

    if game:
        target_word = game.target_word
        ergebnis = wort_uebereinstimmung(target_word, guess)
        print(ergebnis, target_word, sender_sid,game_code)
        emit('guess_result', {'ergebnis': ergebnis, 'sender_sid': sender_sid, 'game_code' : game_code}, broadcast=True)  
        if ergebnis == [1, 1, 1, 1, 1]:
            print("Winner")
            game.winner = user_id
            db.session.commit()

    else:
        emit('error', {'message': 'No target word set'}, broadcast=True)


         
@socketio.on('request_target_word')
def handle_request_target_word(data):
    game_code = data['code']
    game = Game.query.filter_by(game_code=game_code).first()
    target_word = game.target_word
    
    print(target_word)
    if target_word:
        emit('receive_target_word', {'target_word': target_word}, broadcast=True)


@app.route('/newpw')
def newpw():

    return render_template('NewPassword.html')

user_sid_map = {}


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





@app.route('/join', methods=['POST', 'GET'])
@login_required
def join():
    if request.method == 'POST':
        game_code = request.form.get('game_code')  
        if game_code and game_code in rooms:
            game_id = rooms[game_code]
            game = Game.query.get(game_id)
            if game and game.id_Join is None:  
                game.id_Join = current_user.id
                current_time = datetime.now().time()
                game.start_time = current_time
                
                db.session.commit()
                
              
                return redirect(url_for('multiplayer', code=game_code))
            else:
                flash('Das Spiel ist bereits voll oder existiert nicht.')
        else:
            flash('Ungültiger Spielcode.')
    return render_template('Join.html')
 

@app.route('/host', methods=['GET', 'POST'])
@login_required
def host():
    if request.method == 'POST':
        new_game = Game(id_Host=current_user.id)
        db.session.add(new_game)
        db.session.commit()
        
        game_code = generate_unique_code(4)
        rooms[game_code] = new_game.id_game
        session['current_game_code'] = game_code
        new_game.game_code = game_code
        new_game.target_word = get_random_gameword()
        db.session.commit()
        return render_template('Host.html', game_code=game_code)
    return render_template('Host.html')

@app.route('/check_game_status/<code>')
@login_required
def check_game_status(code):
    # Überprüfen Sie den Status des Spiels
    # Beispiel:
    game_id = rooms.get(code)
    if game_id:
        game = Game.query.get(game_id)
        if game and game.id_Join is not None:
            return jsonify({"status": "ready"})
    return jsonify({"status": "waiting"})

@app.route('/settings', methods=['POST','GET'])
@login_required
def settings():
    username = session.get('username')
    email = session.get('e_mail')
    print(username,email)
    return render_template('Settings.html', username=username, email=email)



if __name__ == '__main__':

    app.run(debug=True)
    socketio.run(app)