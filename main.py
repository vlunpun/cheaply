from flask import Flask, render_template, redirect, url_for, flash
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
login_manager.login_view = 'login'

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
    return render_template('register.html', form=form)      #this prints HTML to the webpage

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/', methods=['GET'])
@login_required
def home():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    total_balance = sum(t.amount for t in transactions)
    return render_template('home.html', transactions=transactions, total_balance=total_balance)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        new_transaction = Transaction(description=form.description.data, amount=form.amount.data, currency=form.currency.data, user_id=current_user.id)
        db.session.add(new_transaction)
        db.session.commit()
        flash('Transaction added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_transaction.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

