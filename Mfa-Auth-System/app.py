import pyotp
import qrcode
from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Database setup
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

# Initialize Database
with app.app_context():
    db.create_all()

# Generate QR code for TOTP
def generate_qr_code(secret, username):
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MFA_App")
    qr = qrcode.make(otp_uri)
    qr.save(f'static/{username}_qrcode.png')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists
        if User.query.filter_by(username=username).first():
            return 'Username already exists!'

        otp_secret = pyotp.random_base32()
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()

        generate_qr_code(otp_secret, username)
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('verify_otp'))
        return 'Invalid credentials!'

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        return 'Invalid OTP!'

    return render_template('verify_otp.html', username=username)

@app.route('/dashboard')
def dashboard():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

