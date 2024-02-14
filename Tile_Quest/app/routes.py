from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import login_required, current_user, logout_user, login_user
from app.models import User, Game
from app.utils import admin_required, get_random_gameword, generate_unique_code
from app.forms import LoginForm, RegisterForm
from app.extensions import db, bcrypt
from datetime import datetime
from app.shared import rooms
from app.models import Gamewords


main = Blueprint('main', __name__)

@main.route('/admin_view', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_page(): 
    if request.method == 'POST':
        add_word_text = request.form.get('add_word') 
        existing_word = Gamewords.query.filter_by(words=add_word_text).first()
        
        if existing_word is None and add_word_text:
            new_word=Gamewords(words=add_word_text)
            db.session.add(new_word)
            db.session.commit()
    return render_template('Admin.html')

@main.route('/', methods=['GET', 'POST'])
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
            return redirect(url_for('main.homescreen'))
        else:

            return render_template('Login.html', form=form, error=True)
            
    return render_template('Login.html', form=form)


@main.route('/homescreen', methods=['GET','POST'])
@login_required
def homescreen():
    is_user_admin = session.get('is_user_admin')
    return render_template('Homescreen.html')

@main.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            username_taken = True
            return render_template('Register.html', form=form, username_taken=username_taken)
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
        return redirect(url_for('main.login'))
    return render_template('Register.html', form=form)



@main.route('/privacy_policy')
def dsgvo():
    return render_template('DSGVO.html')

@main.route('/imprint')
def impressum():
    return render_template('Impressum.html')

@main.route('/singleplayer', methods=['POST'])
@login_required
def singleplayer():
    return render_template('Single.html')



@main.route('/multiplayer/<code>', methods=['GET', 'POST'])
@login_required
def multiplayer(code):
    game_id = rooms.get(code)

    session_key = f"multiplayer_access_count_{code}"
    if session_key not in session:
        session[session_key] = 0
    session[session_key] += 1

    if session[session_key] > 1:
        flash('Sie haben die maximale Anzahl von Aufrufen für dieses Spiel erreicht.')
        return redirect(url_for('main.error'))

    game_id = rooms.get(code)
    if not game_id:
        flash('Spiel nicht gefunden.')
        return redirect(url_for('main.error'))  

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
        return redirect(url_for('main.homescreen'))  
    
    
    return render_template('Multi.html', code=code, player=player, opponent=opponent,start_time=start_time)

@main.route('/newpw')
def newpw():
    return render_template('NewPassword.html')

@main.route('/join', methods=['POST', 'GET'])
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
                
              
                return redirect(url_for('main.multiplayer', code=game_code))
            else:
                flash('Das Spiel ist bereits voll oder existiert nicht.')
        else:
            flash('Ungültiger Spielcode.')
    return render_template('Join.html')
 

@main.route('/host', methods=['GET', 'POST'])
@login_required
def host():
    if request.method == 'POST':
        new_game = Game(id_Host=current_user.id)
        db.session.add(new_game)
        db.session.commit()
        
        game_code = generate_unique_code(6)
        rooms[game_code] = new_game.id_game
        session['current_game_code'] = game_code
        new_game.game_code = game_code
        new_game.target_word = get_random_gameword()
        db.session.commit()
        return render_template('Host.html', game_code=game_code)
    return render_template('Host.html')

@main.route('/check_game_status/<code>')
@login_required
def check_game_status(code):
    game_id = rooms.get(code)
    if game_id:
        game = Game.query.get(game_id)
        if game and game.id_Join is not None:
            return jsonify({"status": "ready"})
    return jsonify({"status": "waiting"})

@main.route('/settings', methods=['POST','GET'])
@login_required
def settings():
    username = session.get('username')
    email = session.get('e_mail')
    return render_template('Settings.html', username=username, email=email)

@main.route('/error', methods=['GET', 'POST'])
@login_required
def error():
    return render_template('error.html')