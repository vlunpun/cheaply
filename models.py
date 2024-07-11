from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
import datetime

"""This python file contains classes that represent the structure of our databases. We use SQLAlchemy ORM in these classes to interact with the databses"""

#Insantiate objects of the SQLAlchemy class and LoginManager class
db = SQLAlchemy()
# We use login_manager in the main python file but we are insatiaing the object here 
login_manager = LoginManager()

# Database that represents Users 
class User(UserMixin, db.Model):        #UserMixin is used to provide methods to this class that Flask-Login requires to manage user session. 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

#Database that represents Transactions
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.datetime) 
    category = db.Column(db.String(50), nullable=False)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)   #user_id is a foreignkey that references the User model by its id
