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
        return redirect(url_for('homescreen'))  # Oder eine andere passende Seite
    return decorated_function


@app.route('/admin_view', methods=['GET', 'POST'])
@admin_required
def admin_page():
    return render_template('Admin.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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

    host = db.relationship('User', foreign_keys=[id_Host], backref=db.backref('hosted_games', lazy=True))
    joiner = db.relationship('User', foreign_keys=[id_Join], backref=db.backref('joined_games', lazy=True))
    winner_user = db.relationship('User', foreign_keys=[winner], backref=db.backref('won_games', lazy=True))

class Gamewords(db.Model):
    id_word = db.Column(db.Integer, primary_key = True)
    words = db.Column(db.String)


def add_words(words_):
    for word in words_:
        word_entry = Gamewords(words=word)
        db.session.add(word_entry)

    db.session.commit()


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

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(
         min = 4, max =20)], render_kw = {"placeholder":"Username"})
    
    password = PasswordField(validators = [InputRequired(), Length(
        min = 4, max = 20)], render_kw = {"placeholder": "Password"})
    
    submit = SubmitField("Login")



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

rooms ={}

def generate_unique_code(Length):
    while True:
        code =""
        for _ in range(Length):
            code += random.choice(ascii_uppercase)
        if code not in rooms:
            break
    return code

@app.route('/homescreen', methods=['GET','POST'])
@login_required
def homescreen():
    is_user_admin = session.get('is_user_admin')
    return render_template('Homescreen.html')


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
    # Hier können Sie Ihre Spiellogik implementieren
    return render_template('Multi.html', code=code)


@app.route('/newpw')
def newpw():

    return render_template('NewPassword.html')


@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
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
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -=1
        if rooms[room]["members"] <=0:
            del rooms[room]
    send({"name": name, "message" : "has left the room"}, to=room)
    print(f"{name} left the room{room}")


@socketio.on('spieleraktion')
def spieleraktion(data):
    # Verarbeiten der Spieleraktion
    # Beispiel: Aktualisieren des Spielstands oder Verarbeiten einer Nachricht
    # Rücksenden der Antwort an die Spieler
    emit('spielupdate', response_data, to=room)


@app.route('/join', methods=['POST', 'GET'])
@login_required
def join():
    if request.method == 'POST':
        game_code = request.form.get('game_code')  # Verwendung von runden Klammern
        if game_code and game_code in rooms:
            game_id = rooms[game_code]
            game = Game.query.get(game_id)
            if game and game.id_Join is None:  
                game.id_Join = current_user.id
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