from flask import Flask, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import wtforms
from wtforms import Form, StringField, PasswordField, SubmitField, validators
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/maximilianherzog/Desktop/Entwicklung/Web-Technologie/Web-Technologie/Wordle/venv/database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(80), nullable = False)
    secure_question = db.Column(db.String(80), nullable = False)
    e_mail = db.Column(db.String(80), nullable = False)
"""
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
"""

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

@app.route('/')
def home():
    return render_template('home.html') #Benni Prüfen

@app.route('/login') 
def home():
    return render_template('login.html') #Benni Prüfen

@app.route('/register')
def home():
    return render_template('register.html') #Benni Prüfen

if __name__ == '__main__':
    app.run(debug = True)

def index():
    return render_template("index.html") #Benni Prüfen

