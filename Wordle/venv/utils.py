from functools import wraps
from flask import session, flash, redirect, url_for
import random
from venv.models import User, Gamewords
from string import ascii_uppercase
from venv.shared import rooms

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

def get_random_gameword():
    count = Gamewords.query.count()
    if count == 0:
        return None  # Keine Wörter in der Datenbank
    random_index = random.randint(0, count - 1)
    random_word = Gamewords.query.offset(random_index).first()
    return random_word.words if random_word else None

def generate_unique_code(Length):
    while True:
        code =""
        for _ in range(Length):
            code += random.choice(ascii_uppercase)
        if code not in rooms:
            break
    return code