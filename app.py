from flask import Flask, render_template, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from otp import generate_otp, validate_otp
from forms import SignupForm, LoginForm, OTPForm, SectionSearchForm, FIRSearchForm, BailForm
from config import Config
from models import User,Section,Case,Petition
from datetime import datetime

app = Flask(__name__)
app.config.from_object(Config)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({'_id': user_id})
    if user:
        return User(user)
    return None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_data = {
            'aadhar': form.aadhar.data,
            'password': hashed_password,
            'user_type': form.user_type.data,
            'identification': form.identification.data if form.user_type.data != 'UP' else None
        }
        mongo.db.users.insert_one(user_data)
        flash('Account created successfully.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = mongo.db.users.find_one({'aadhar': form.aadhar.data})
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            otp = generate_otp(user['_id'])
            session['otp_user_id'] = str(user['_id'])
            flash(f"OTP sent to your contact: {otp}", 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Login failed. Check credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        user_id = session.get('otp_user_id')
        if user_id and validate_otp(user_id, form.otp.data):
            user = mongo.db.users.find_one({'_id': user_id})
            login_user(User(user))
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP.', 'danger')
    return render_template('verify_otp.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    user_type = current_user.user_type
    if user_type == 'UP':
        return redirect(url_for('up_dashboard'))
    elif user_type == 'LegalAid':
        return redirect(url_for('legal_dashboard'))
    elif user_type == 'JudicialAuthority':
        return redirect(url_for('judicial_dashboard'))

@app.route('/up_dashboard')
@login_required
def up_dashboard():
    return render_template('up_dashboard.html')

@app.route('/up/view_reckoner', methods=['GET', 'POST'])
@login_required
def view_reckoner():
    form = SectionSearchForm()
    if form.validate_on_submit():
        section = mongo.db.sections.find_one({'section': form.section.data})
        return render_template('reckoner_result.html', section=section)
    return render_template('view_reckoner.html', form=form)

@app.route('/up/view_case', methods=['GET', 'POST'])
@login_required
def view_case():
    form = FIRSearchForm()
    if form.validate_on_submit():
        case = mongo.db.cases.find_one({'fir': form.fir.data})
        return render_template('case_result.html', case=case)
    return render_template('view_case.html', form=form)

@app.route('/up/check_eligibility', methods=['GET', 'POST'])
@login_required
def check_eligibility():
    form = FIRSearchForm()
    if form.validate_on_submit():
        case = mongo.db.cases.find_one({'fir': form.fir.data})
        section = mongo.db.sections.find_one({'section': case['section']})
        eligible = section['eligibility']
        return render_template('eligibility_result.html', eligible=eligible)
    return render_template('check_eligibility.html', form=form)

# More routes for Legal Aid Provider and Judicial Authority can be added similarly.
# Continuation of app.py

# Legal Aid Provider Dashboard
@app.route('/legal_dashboard')
@login_required
def legal_dashboard():
    if current_user.user_type != 'LegalAid':
        return redirect(url_for('dashboard'))  # Redirect if not legal aid provider
    return render_template('legal_dashboard.html')

# Generate Bail Petition
@app.route('/legal/generate_bail', methods=['GET', 'POST'])
@login_required
def generate_bail():
    if current_user.user_type != 'LegalAid':
        return redirect(url_for('dashboard'))  # Only for Legal Aid Providers
    form = BailForm()
    if form.validate_on_submit():
        bail_data = {
            'fir': form.fir.data,
            'bail_details': form.bail_details.data,
            'status': 'pending',
            'submitted_at': datetime.utcnow()
        }
        mongo.db.petitions.insert_one(bail_data)
        flash('Bail petition submitted successfully.', 'success')
        return redirect(url_for('monitor_status'))
    return render_template('generate_bail.html', form=form)

# Monitor Bail Petition Status
@app.route('/legal/monitor_status', methods=['GET', 'POST'])
@login_required
def monitor_status():
    if current_user.user_type != 'LegalAid':
        return redirect(url_for('dashboard'))  # Only for Legal Aid Providers
    form = FIRSearchForm()
    if form.validate_on_submit():
        petition = mongo.db.petitions.find_one({'fir': form.fir.data})
        return render_template('monitor_status.html', petition=petition)
    return render_template('monitor_status_search.html', form=form)

# Judicial Authority Dashboard
@app.route('/judicial_dashboard')
@login_required
def judicial_dashboard():
    if current_user.user_type != 'JudicialAuthority':
        return redirect(url_for('dashboard'))  # Redirect if not judicial authority
    return render_template('judicial_dashboard.html')

# Review Bail Petitions
@app.route('/judicial/review_bail', methods=['GET', 'POST'])
@login_required
def review_bail():
    if current_user.user_type != 'JudicialAuthority':
        return redirect(url_for('dashboard'))  # Only for Judicial Authorities
    pending_petitions = mongo.db.petitions.find({'status': 'pending'})
    return render_template('review_bail.html', petitions=pending_petitions)

# Accept or Reject Bail Petition
@app.route('/judicial/review_bail/<petition_id>/<action>', methods=['POST'])
@login_required
def handle_bail_petition(petition_id, action):
    if current_user.user_type != 'JudicialAuthority':
        return redirect(url_for('dashboard'))  # Only for Judicial Authorities
    petition = mongo.db.petitions.find_one({'_id': petition_id})
    if petition and action in ['accept', 'reject']:
        new_status = 'accepted' if action == 'accept' else 'rejected'
        mongo.db.petitions.update_one(
            {'_id': petition_id},
            {'$set': {'status': new_status, 'reviewed_at': datetime.utcnow()}}
        )
        flash(f'Bail petition {new_status}.', 'success')
        return redirect(url_for('review_bail'))
    flash('Invalid action or petition.', 'danger')
    return redirect(url_for('review_bail'))
