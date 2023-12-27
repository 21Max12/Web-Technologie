import FlaskForm
from wtforms import Form, StringField, PasswordField, SubmitField, validators, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Optional, Email


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)])
    e_mail = StringField(validators=[Optional(), Email()], render_kw={"placeholder": "E-Mail"})
    security_question = SelectField('Security Question', choices=[('Pet', "What's the name of your first pet?"), ('Car', "What was your first car?"), ('Mother', "What is the mother's surname?")], validators=[InputRequired()])
    security_answer = StringField('Security Answer', validators=[InputRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(
         min = 4, max =20)], render_kw = {"placeholder":"Username"})
    
    password = PasswordField(validators = [InputRequired(), Length(
        min = 4, max = 20)], render_kw = {"placeholder": "Password"})
    
    submit = SubmitField("Login")