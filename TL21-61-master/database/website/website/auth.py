from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, make_response
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import jwt
import datetime
from functools import wraps

auth = Blueprint('auth', __name__)

#auth.config['SECRET KEY'] = 'danga'
secret = 'danga'

#def token_required(f):
 #   @wraps(f)
  #  def decorated(*args, **kwargs):
   #     token = request.args.get('token')
        
    #    try:
     #       data = jwt.decode(token, secret)
        
      #  except:
       #     return jsonify({'message' : 'Token is invalid or expired'})
            
        #return f(*args, **kwargs)
    
    #return decorated

# token = request.post(localhost:5000/login)
# if token:
#     user = token.decode
#     insertLocalStorage(token)
#     redirect url_for(views.home)

#@auth.route('/protected')
#@token_required
#def protected():
 #   return redirect(url_for('views.home'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                token = jwt.encode({'email' : user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, secret) #to datetime me to timedelta to vazw gia na kanei expire to token meta apo 60 lepta gia asfaleia
                
                # return jsonify({'token' : token}) #return the token to the user, we want to return it as json so we use jsonify, epeidh eimai sth python3 kanw decode to token gia na ginei string
                
                token = token.decode('UTF-8')

                return {'token': token}

                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif len(last_name) < 2:
            flash('Last name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, last_name=last_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)