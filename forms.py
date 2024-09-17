from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, Email

class SignupForm(FlaskForm):
    aadhar = StringField('Aadhar Number', validators=[DataRequired(), Length(min=12, max=12)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    user_type = SelectField('User Type', choices=[('UP', 'UP'), ('LegalAid', 'Legal Aid Provider'), ('JudicialAuthority', 'Judicial Authority')], validators=[DataRequired()])
    identification = FileField('Identification (Only for Legal Aid or Judicial Authority)')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    aadhar = StringField('Aadhar Number', validators=[DataRequired(), Length(min=12, max=12)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class SectionSearchForm(FlaskForm):
    section = StringField('Section Number', validators=[DataRequired()])
    submit = SubmitField('Search')

class FIRSearchForm(FlaskForm):
    fir = StringField('FIR Number', validators=[DataRequired()])
    submit = SubmitField('Search')

class BailForm(FlaskForm):
    fir = StringField('FIR Number', validators=[DataRequired()])
    bail_details = StringField('Bail Details', validators=[DataRequired()])
    submit = SubmitField('Generate Bail')
