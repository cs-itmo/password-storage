from flask import Flask, render_template, request, redirect, session, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import uuid
import logging
import secrets
import os
from flask import Flask, send_from_directory, render_template_string, abort

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
STATIC_DIR = os.path.join(app.root_path, 'static')
app.secret_key = secrets.token_bytes(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    join_code = db.Column(db.String(36), unique=True)

class Membership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    organization_id = db.Column(db.Integer)
    role = db.Column(db.String(10))  # "admin" or "user"

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    organization_id = db.Column(db.Integer)
    service = db.Column(db.String(120))
    secret = db.Column(db.String(120))

def get_current_user():
    if 'user_id' not in session:
        return None
    org_id = request.args.get('org_id', type=int, default=None)
    membership = None
    if org_id is not None:
        membership = Membership.query.filter_by(user_id=session['user_id'], organization_id=org_id).first()
    return User.query.get(session['user_id']), membership

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        existing_user = User.query.filter_by(username=request.form['username']).first()
        if existing_user:
            return render_template('register.html', error="Username already exists.")
        hashed = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=request.form['username'], password=hashed)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    user, _ = get_current_user()
    if not user:
        return redirect(url_for('login'))
    memberships = Membership.query.filter_by(user_id=user.id).all()
    organizations = [Organization.query.get(m.organization_id) for m in memberships]
    return render_template('dashboard.html', organizations=organizations)

@app.route('/organization/create', methods=['GET', 'POST'])
def create_organization():
    user, _ = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        join_code = str(uuid.uuid4())
        org = Organization(name=request.form['name'], join_code=join_code)
        db.session.add(org)
        db.session.commit()
        membership = Membership(user_id=user.id, organization_id=org.id, role='admin')
        db.session.add(membership)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('create_organization.html')

@app.route('/organization/join', methods=['GET', 'POST'])
def join_organization():
    user, _ = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        org = Organization.query.filter_by(join_code=code).first()
        if org:
            existing = Membership.query.filter_by(user_id=user.id, organization_id=org.id).first()
            if not existing:
                membership = Membership(user_id=user.id, organization_id=org.id, role='user')
                db.session.add(membership)
                db.session.commit()
            return redirect(url_for('dashboard'))
    return render_template('join_organization.html')

@app.route('/organization/<int:org_id>', methods=['GET', 'POST'])
def organization_page(org_id):
    user, membership = get_current_user()
    if not user:
        return redirect(url_for('login'))

    if not membership:
        membership = Membership.query.filter_by(user_id=user.id, organization_id=org_id).first()
        if not membership:
            abort(403)

    if request.method == 'POST':
        new_pw = Password(
            user_id=user.id,
            organization_id=org_id,
            service=request.form['service'],
            secret=request.form['secret']
        )
        db.session.add(new_pw)
        db.session.commit()
        return redirect(url_for('organization_page', org_id=org_id))

    if membership.role == 'admin':
        passwords = Password.query.filter_by(organization_id=org_id).all()
    else:
        passwords = Password.query.filter_by(organization_id=org_id, user_id=user.id).all()

    return render_template('organization.html', membership=membership, passwords=passwords, role=membership.role, join_code=Organization.query.get(org_id).join_code)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=False)
