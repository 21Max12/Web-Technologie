from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, SubmitField, validators
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import datetime
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/maximilianherzog/Desktop/Entwicklung/Web-Technologie/Web-Technologie/Wordle/venv/database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(80), nullable = False)
    secure_question = db.Column(db.String(80), nullable = False)
    e_mail = db.Column(db.String(80), nullable = False)



class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(
         min = 4, max =20)], render_kw = {"placeholder":"Username"})
    
    password = PasswordField(validators = [InputRequired(), Length(
        min = 4, max = 20)], render_kw = {"placeholder": "Password"})
    
    submit = SubmitField("Register")

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
"""
@app.route('/')
def home():
    return render_template('home.html')
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('Homescreen'))
        else:
            # Hier könnten Sie eine Fehlermeldung hinzufügen
            pass
    return render_template('Login.html', form=form)


@app.route('/homescreen', methods=['GET','POST'])
@login_required
def Homescreen():
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
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        secure_question = request.form['security_question']
        e_mail = request.form['e_mail']  # Stellen Sie sicher, dass dieses Feld im Formular existiert
        new_user = User(username=form.username.data, password=hashed_password, secure_question=secure_question, e_mail=e_mail)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('Register.html', form=form)




if __name__ == '__main__':
    app.run(debug = True)

def index():
    return render_template("index.html") #Benni Prüfen

