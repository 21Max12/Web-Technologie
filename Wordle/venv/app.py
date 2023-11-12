from flask import Flask, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/maximilianherzog/Desktop/Entwicklung/Web-Technologie/Web-Technologie/Wordle/venv/database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False)
    password = db.Column(db.String(80), nullable = False)

#if __name__ == '__main__':
   # with app.app_context():
     #   db.create_all()
 #   app.run(debug=True)

    
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

