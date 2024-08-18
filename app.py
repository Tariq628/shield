from flask import Flask, render_template, url_for, redirect, flash, request, jsonify, session, send_file, abort
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
from dotenv import load_dotenv
import os
import pandas as pd
from forms import AddEmployeeForm, UserForm, VoteForm
from flask_migrate import Migrate
from datetime import datetime, timedelta
from flask_cors import CORS

load_dotenv()

csrf = CSRFProtect()


app = Flask(__name__)
CORS(app, origins="*")  # Allows all origins
csrf.init_app(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'thisisasecretkey')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)

# Configure session
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_KEY_PREFIX'] = 'session:'

# Cookie settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# Initialize extensions
mail = Mail(app)
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
bcrypt = Bcrypt(app)
sess = Session(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Push the app context
app.app_context().push()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=True)
    first_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    has_set_password = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt=app.config['SECRET_KEY'])

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt=app.config['SECRET_KEY'], max_age=expires_sec)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_first_name = db.Column(db.String(150), nullable=False)
    user_last_name = db.Column(db.String(150), nullable=False)
    user_email = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(min=4, max=150)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


@app.route('/')
def home():
    print('current_user.is_authenticated')
    print(current_user.is_authenticated)
    for ses in session:
        print(ses, session[ses])

    form = LoginForm()
    return render_template('index.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.password is None:
                # First time login, set the password
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user.password = hashed_password
                user.has_set_password = True
                db.session.commit()
                login_user(user)
                flash('Password set successfully!', 'success')
                return redirect(url_for('home'))
            elif bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                # session.permanent = True
                return redirect(url_for('home'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
        
    return render_template('index.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()  # Clear the session on logout
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/reset_password_admin/<int:user_id>', methods=['POST'])
@login_required
def reset_password_admin(user_id):
    if not current_user.is_admin:
        flash('You do not have access to this action.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if user:
        user.password = None
        user.has_set_password = False
        db.session.commit()
        flash(f'The password for {user.email} has been reset to: password not yet set', 'success')
    return redirect(url_for('admin'))

@app.route('/edit_user', methods=['POST'])
@login_required
def edit_user():
    user_id = request.form['user_id']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    is_admin = request.form.get('is_admin') == 'on'
    
    user = User.query.get(user_id)
    if user:
        user.first_name = first_name
        user.last_name = last_name
        user.is_admin = is_admin
        db.session.commit()
        flash('User updated successfully.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/toggle_admin', methods=['POST'])
@login_required
def toggle_admin():
    if not current_user.is_admin:
        return redirect(url_for('home'))

    user_id = request.form['user_id']
    user = User.query.get(user_id)
    if user:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash('User admin status updated successfully', 'success')
    else:
        flash('User not found', 'error')

    return redirect(url_for('admin'))

@app.route('/reset_votes', methods=['POST'])
@login_required
def reset_votes():
    if not current_user.is_admin:
        flash('You do not have access to this action.', 'danger')
        return redirect(url_for('admin'))
    
    try:
        Vote.query.delete()
        db.session.commit()
        flash('All votes have been reset.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting votes: {e}', 'danger')

    return redirect(url_for('admin'))

@app.route('/export_votes')
@login_required
def export_votes():
    if not current_user.is_admin:
        abort(403)

    votes = Vote.query.all()
    votes_data = [{
        'ID': vote.id,
        'Name': vote.name,
        'Category': vote.category,
        'Location': vote.location,
        'Description': vote.description,
        'Submitted By': f'{vote.user_first_name} {vote.user_last_name}',
        'Email': vote.user_email,
        'Timestamp': vote.timestamp
    } for vote in votes]

    df = pd.DataFrame(votes_data)
    directory = os.path.join(os.getcwd(), 'tmp')
    if not os.path.exists(directory):
        os.makedirs(directory)
    csv_path = os.path.join(directory, 'votes_export.csv')
    df.to_csv(csv_path, index=False)

    return send_file(csv_path, as_attachment=True, download_name='votes_export.csv')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('home'))

    users = User.query.all()
    votes = Vote.query.all()
    form = UserForm()
    add_employee_form = AddEmployeeForm()

    if add_employee_form.validate_on_submit():
        new_email = add_employee_form.email.data
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user:
            flash('This email already exists in the database.', 'danger')
        else:
            new_user = User(email=new_email, password=None, has_set_password=False)
            db.session.add(new_user)
            db.session.commit()
            flash('New employee added successfully.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin_view.html', users=users, votes=votes, form=form, add_employee_form=add_employee_form)

@app.route('/make_admin/<int:user_id>')
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if user:
        user.is_admin = True
        db.session.commit()
        flash('User has been made an admin.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have access to this action.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
    return redirect(url_for('admin'))

@app.route('/session-status')
def session_status():
    if current_user.is_authenticated:
        return jsonify({
            'loggedIn': True,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name
        })
    else:
        return jsonify({'loggedIn': False})

@app.route('/contact.html')
@login_required
def contact():
    form = VoteForm()
    return render_template('contact.html', form=form)

@app.route('/submit', methods=['POST'])
@login_required
def submit_vote():
    form = VoteForm()
    if form.validate_on_submit():
        new_vote = Vote(
            name=form.name.data,
            category=form.category.data,
            location=form.location.data,
            description=form.description.data,
            user_id=current_user.id,
            user_first_name=current_user.first_name,
            user_last_name=current_user.last_name,
            user_email=current_user.email
        )
        db.session.add(new_vote)
        db.session.commit()
        flash('Vote submitted successfully!', 'success')
        return redirect(url_for('contact'))
    else:
        flash('Error submitting vote', 'danger')
        return redirect(url_for('contact'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
