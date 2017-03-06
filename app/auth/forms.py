from flask.ext.login import current_user
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Required, Email, Length, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Email(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login')
    
    
class RegistrationFrom(Form):
    email = StringField('Email', validators=[Required(), Email(), Length(1, 64)])
    username = StringField('Username', validators=[Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$',
        0, 'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo('confirmPassword', 
        message="Passwords must match.")]);
    confirmPassword = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Register')
    
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Account already registered with this email')
    
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('username already exists')
            

class PasswordChangeForm(Form):
    password = PasswordField('Current Password', validators=[Required(), Length(1, 64)])
    new_password1 = PasswordField('New Password', validators=[Required(), Length(1, 64), 
        EqualTo('new_password2', message="New Passwords Must Match.")])
    new_password2 = PasswordField('Confirm New Password', validators=[Required(), Length(1, 64)])
    submit = SubmitField('Change Password');
    
    
    def validate_password(self, field):
        print field.data
        if not current_user.verify_password(field.data):
            raise ValidationError('Current Password Invalid.')