from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DecimalField, SubmitField, SelectField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TransactionForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[DataRequired()])
    currency = SelectField('Currency', choices=[('USD', 'USD'), ('EUR', 'EUR')], validators=[DataRequired()])    
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])  
    category = SelectField('Category', choices=[
        ('Mortgage or Rent', 'Mortgage or Rent'), ('Food and Drinks', 'Food and Drinks'), ('Transportation', 'Transportation'),
        ('Utilities', 'Utilities'), ('Travel', 'Travel'), ('Personal expenses', 'Personal expenses'), ('Child care', 'Child care'),
        ('Savings/Investing', 'Savings/Investing'), ('Loan payments', 'Loan payments'), ('Healthcare', 'Healthcare'),
        ('Pets', 'Pets'), ('Miscellaneous', 'Miscellaneous')
        ], validators=[DataRequired()])
    submit = SubmitField('Add Transaction')

class IncomeForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[DataRequired()])
    currency = SelectField('Currency', choices=[('USD', 'USD'), ('EUR', 'EUR'), ('GBP', 'GBP')], validators=[DataRequired()])
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Job', 'Job'), 
        ('Business', 'Business'), 
        ('Side Hustles', 'Side Hustles'), 
        ('Investments', 'Investments'), 
        ('Other', 'Other')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Income')

