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




