from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Email, Length

class AddEmployeeForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Add Employee')

class UserForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    new_password = PasswordField('New Password', validators=[InputRequired()])
    submit = SubmitField('Update Password')

class VoteForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    category = SelectField('Category', choices=[
        ('Safety', 'Safety'),
        ('Honesty', 'Honesty'),
        ('Integrity', 'Integrity'),
        ('Excellence', 'Excellence'),
        ('Leadership', 'Leadership'),
        ('Dependability', 'Dependability')
    ], validators=[InputRequired()])
    location = StringField('Location', validators=[InputRequired()])
    description = TextAreaField('Description', validators=[InputRequired()])
    submit = SubmitField('Submit')
