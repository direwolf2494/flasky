from flask import render_template, url_for, flash, redirect, request
from flask.ext.login import login_user, logout_user, login_required, current_user
from .forms import LoginForm, RegistrationFrom, PasswordChangeForm
from ..models import User
from ..email import send_email
from . import auth
from .. import db

@auth.before_app_request
def before_request():
    print request.endpoint
    if current_user.is_authenticated and \
      not current_user.confirmed and \
      request.endpoint[:4] != 'auth':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or Password')
    return render_template('auth/login.html', form=form)
    
    
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('main.index'))
    
    
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationFrom();
    if form.validate_on_submit():
        user = User(email=form.email.data, 
                    username=form.username.data, 
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_mail(user.email, 'Confirm Your Account', 'auth/email/confirm',
            user=user, token=token)
        flash('A confirmation email has been sent to the address you provided.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)
    
    
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_mail(current_user.email, 'Confirm Your Account', user=user,
        token=token)
    flash('Another Confirmation email was sent to your email address.')
    return redirect('main.index')
    

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have successfully confirmed you email.')
    else:
        flash('The confirmation link is either invalid or expired.')
    return redirect(url_form('main.index'))
    

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect('main.index')
    return render_template('auth/unconfirmed.html')
        
        
@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        current_user.password = form.new_password1.data
        return redirect(url_for('main.index'))
    return render_template('auth/change_password.html', form=form)