from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crochet.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/images')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max limit for image uploads

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from forms import RegistrationForm, LoginForm, PatternForm

# Define models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    patterns = db.relationship('Pattern', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Pattern(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100), nullable=False, default='default.jpg')
    instructions = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Tạo tất cả các bảng (được di chuyển vào init_db.py)
# db.create_all()

# Login manager loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    patterns = Pattern.query.order_by(Pattern.created_at.desc()).all()
    return render_template('index.html', patterns=patterns)

@app.route('/pattern/<int:pattern_id>')
def pattern(pattern_id):
    pattern = Pattern.query.get_or_404(pattern_id)
    return render_template('pattern.html', pattern=pattern)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = PatternForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        instructions = form.instructions.data
        image = form.image.data
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        new_pattern = Pattern(name=name, description=description, instructions=instructions, image=filename, user_id=current_user.id)
        db.session.add(new_pattern)
        db.session.commit()
        flash('Pattern created successfully', 'success')
        return redirect(url_for('index'))
    return render_template('create_pattern.html', form=form)

@app.route('/edit/<int:pattern_id>', methods=['GET', 'POST'])
@login_required
def edit(pattern_id):
    pattern = Pattern.query.get_or_404(pattern_id)
    form = PatternForm(obj=pattern)
    if form.validate_on_submit():
        pattern.name = form.name.data
        pattern.description = form.description.data
        pattern.instructions = form.instructions.data
        image = form.image.data
        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            pattern.image = filename
        db.session.commit()
        flash('Pattern updated successfully', 'success')
        return redirect(url_for('pattern', pattern_id=pattern.id))
    return render_template('edit_pattern.html', form=form, pattern=pattern)

@app.route('/delete/<int:pattern_id>', methods=['POST'])
@login_required
def delete(pattern_id):
    pattern = Pattern.query.get_or_404(pattern_id)
    db.session.delete(pattern)
    db.session.commit()
    flash('Pattern deleted successfully', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
