from functools import wraps
from flask import session, flash, redirect, url_for
import random
from .models import User, Gamewords
from string import ascii_uppercase
from .shared import rooms, user_sid_map


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        is_user_admin = session.get('is_user_admin')
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




def get_user_id_from_sid(sender_sid):
    return user_sid_map.get(sender_sid)

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