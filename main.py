from flask import Flask, render_template, redirect, url_for, flash, request
from forms import RegistrationForm, LoginForm, TransactionForm
from models import db, login_manager, User, Transaction
from flask_bcrypt import Bcrypt
from flask_login import login_user, current_user, logout_user, login_required

# configure application objects
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance_tracker.db'
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager.init_app(app)
login_manager.login_view = 'login'      #specifies the route to redirect users if they need to login

# This callback is used to reload the user object from the user ID stored in the session.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():       #checks if entries in registration form are valid
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')        #hashes password that is entered in the registration form
        # sends form data to database
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)       
        db.session.add(user)
        db.session.commit()
        # flashes a success message after account is created
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))       # if entry is valid then redirect to login page
    return render_template('register.html', form=form)      

@app.route('/login', methods=['GET', 'POST'])
def login():
    # if user is authenticated the this prevents logged-in users from accessing the login page again and redirects them to home 
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():       #checks if entries in login form are valid
        user = User.query.filter_by(email=form.email.data).first()      #queries the User table to find the first user with the email address entered in the form. If not then user is None
        if user and bcrypt.check_password_hash(user.password, form.password.data):      #entered password is compared to the hashed password stored in the database
            login_user(user, remember=True)         #login_user logs in a user and the remember=True saves a cookie will on the user’s computer to remember the user
            return redirect(url_for('home'))        #redirects to homepage once logged in
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')      #if invalid login then flash message
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/', methods=['GET'])
@login_required
def home():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()       #queries all the transactions for the current user
    total_balance = sum(t.amount for t in transactions)         #adds them up to display total amount in the home page
    return render_template('home.html', transactions=transactions, total_balance=total_balance)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        # sends form data to database
        new_transaction = Transaction(
            description=form.description.data,
            amount=form.amount.data,
            currency=form.currency.data,
            date=form.date.data,
            category=form.category.data,
            user_id=current_user.id
            )
        db.session.add(new_transaction)
        db.session.commit()
        flash('Transaction added successfully!', 'success')     #if valid then flash method
        return redirect(url_for('add_transaction'))         #redirect to same page to reset form entries
    return render_template('add_transaction.html', form=form)

@app.route('/delete', methods=['POST'])
@login_required
def delete_transaction():
    transaction_id = request.form.get('transaction_id')     # Get the transaction ID from the form data (the form data in the home.html)
    transaction = Transaction.query.get(transaction_id)     # Query the transaction from the database
    db.session.delete(transaction)      # Delete the transaction from the database
    db.session.commit()     # Commit the changes to the database
    flash('Transaction deleted successfully!', 'success')   # Flash message once deleted
    return redirect(url_for('home'))    # Refresh the page

if __name__ == '__main__':
    with app.app_context():
        db.create_all()         # This ensures the tables are created before the app starts
    app.run(debug=True)