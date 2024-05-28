from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import os
import random
import secrets
import string
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    plain_password = db.Column(db.String(100), nullable=False)  # Added field for plaintext password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


if not os.path.exists('passwords.db'):
    with app.app_context():
        db.create_all()
        print("Database created successfully!")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/splash-screen')
def splash_screen():
    return render_template('splash_screen.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    errors = {}
    form_data = {'username': '', 'email': ''}
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        form_data['username'] = username
        form_data['email'] = email

        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            if user_exists.username == username:
                errors['username'] = 'Цей нікнейм уже зайнятий.'
            if user_exists.email == email:
                errors['email'] = 'Ця електронна пошта уже зайнята.'
            return render_template('register.html', errors=errors, form=form_data)
        
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Реєстрація успішна!', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html', errors=errors, form=form_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    errors = {}
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Успішний вхід!', 'success')
            return redirect(url_for('index'))
        else:
            if not user:
                errors['username'] = 'Невірне ім\'я користувача'
            else:
                errors['password'] = 'Невірний пароль'
            return render_template('login.html', errors=errors)
    return render_template('login.html')

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    generated_password = None
    if request.method == 'POST':
        min_length = int(request.form['min_length'])
        max_length = int(request.form['max_length'])
        include_lowercase = 'include_lowercase' in request.form
        include_uppercase = 'include_uppercase' in request.form
        include_digits = 'include_digits' in request.form
        include_special_characters = 'include_special_characters' in request.form
        
        generated_password = generate_custom_password(min_length, max_length, include_lowercase, include_uppercase, include_digits, include_special_characters)
        hashed_password = generate_password_hash(generated_password)
        user_id = session['user_id']
        new_password = Password(user_id=user_id, password=hashed_password, plain_password=generated_password)  # Store plaintext password
        db.session.add(new_password)
        db.session.commit()
    
    user_id = session['user_id']
    passwords = Password.query.filter_by(user_id=user_id).order_by(Password.created_at.desc()).all()
    return render_template('generate_password.html', passwords=passwords, generated_password=generated_password)



def generate_custom_password(min_length, max_length, include_lowercase, include_uppercase, include_digits, include_special_characters):
    characters = ''
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special_characters:
        characters += string.punctuation
    
    password_length = random.randint(min_length, max_length)
    password = ''.join(secrets.choice(characters) for _ in range(password_length))
    
    return password

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
