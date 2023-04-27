import logging
from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_from_directory
from forms import RegisterForm, LoginForm, EditUserForm
from config import Config
from datetime import datetime
from flask_wtf import csrf
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_uploads import UploadSet, configure_uploads
from flask_sqlalchemy import SQLAlchemy
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash



import os

app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOADED_FILES_DEST'] = 'uploads'  # dossier de stockage des fichiers uploadés
uploaded_files = UploadSet('files', ('csv', 'doc', 'docx', 'txt', 'pdf'))
configure_uploads(app, uploaded_files)

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

class BankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    content_type = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.Integer, nullable=False, default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Inscription réussie !', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Username ou mot de passe invalide', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)  # Accès refusé
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)  # Accès refusé

    user = User.query.get(user_id)
    if user is None:
        abort(404)  # Utilisateur non trouvé

    form = EditUserForm()
    if request.method == 'POST' and form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.is_admin = form.is_admin.data
        db.session.commit()
        flash('Les informations de l\'utilisateur ont été mises à jour avec succès.', 'success')
        return redirect(url_for('admin'))

    form.username.data = user.username
    form.email.data = user.email
    form.is_admin.data = user.is_admin

    return render_template('edit_user.html', form=form, user_id=user_id)
    
@app.route('/mybank')
@login_required
def mybank():
    return render_template('mybank.html', username=current_user.username)

@app.route('/myfiles')
@login_required
def myfiles():
    files = UploadedFile.query.filter_by(user_id=current_user.id).all()
    return render_template('myfiles.html', files=files)


@app.route('/myfiles/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Aucun fichier sélectionné', 'danger')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('Aucun fichier sélectionné', 'danger')
        return redirect(request.url)

    if file and uploaded_files.file_allowed(file, file.filename):
        filename = uploaded_files.save(file)
        file_size = os.path.getsize(os.path.join(app.config['UPLOADED_FILES_DEST'], filename))
        uploaded_file = UploadedFile(
            filename=filename,
            size=file_size,
            content_type=file.content_type,
            user_id=current_user.id
        )
        db.session.add(uploaded_file)
        db.session.commit()
        flash(f'Le fichier {filename} a été uploadé avec succès', 'success')
        return redirect(url_for('myfiles'))
    else:
        flash('Le format de fichier est incorrect', 'danger')
        return redirect(url_for('myfiles'))


@app.route('/myfiles/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = UploadedFile.query.get(file_id)
    if not file:
        abort(404)
    return send_from_directory(app.config['UPLOADED_FILES_DEST'], uploaded_files.path(file.filename), as_attachment=True)
    

@app.route('/delete_user/<int:user_id>', methods=['POST', 'DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('L\'utilisateur a été supprimé avec succès.', 'success')
    return redirect(url_for('admin'))
    

if __name__ == '__main__':
    handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.run(host='0.0.0.0', port=5000, debug=True)