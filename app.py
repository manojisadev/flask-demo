from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask_mongoengine import MongoEngine

app = Flask(__name__)
app.config["SECRET_KEY"] = 'secret123' #import from config files
app.config['SESSION_TYPE'] = 'filesystem'
# app.config['MONGODB_SETTINGS'] = {
#     'DB': 'yelptest',
#     'host': 'mongodb://localhost:27017'
# }
app.config['MONGODB_SETTINGS'] = {
    'db': 'yelptest',
    'host': 'localhost',
    'port': 27017
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/testdb'

db = SQLAlchemy(app)

dbm = MongoEngine(app)
db.init_app(app)

class business(dbm.DynamicDocument):
	name = dbm.StringField()
	city = dbm.StringField()


class User(db.Model):
	__tablename__ = 'Users'
	uid = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(20))
	first_name = db.Column(db.String(20))
	last_name = db.Column(db.String(20))
	email = db.Column(db.String(20), unique = True)
	password = db.Column(db.String(120))

@app.route('/')
def index():
	return render_template('index.html')

class RegisterForm(Form):
	first_name = StringField('First Name', [validators.Length(min = 5, max = 20)])
	last_name = StringField('Last Name', [validators.Length(min = 5, max = 20)])
	username = StringField('Username', [validators.Length(min = 5, max = 20)])
	email = StringField('Email', [validators.Length(min = 5, max = 20)])
	password = PasswordField('Password', [
		validators.Length(min = 6, max = 50, message = 'Passwords must be a minimum of length 6'),
		validators.DataRequired(), 
		validators.EqualTo('confirm', message = 'Passwords must match')])
	confirm = PasswordField('Confirm Password', [validators.DataRequired()])

class LoginForm(Form):
	username = StringField('Username', [validators.Length(min = 5, max = 20)])
	password_submitted = PasswordField('Password', [validators.DataRequired()])

class SearchForm(Form):
	search_field = StringField('City Name')

@app.route('/register', methods = ['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		first_name = form.first_name.data
		last_name = form.last_name.data
		username = form.username.data
		email = form.email.data
		password = sha256_crypt.encrypt(str(form.password.data))
		user = User(
			first_name = first_name, 
			last_name = last_name, 
			username = username, 
			email = email,
			password = password)
		db.session.add(user)
		db.session.commit()
		flash('Account created!', 'success')
		return redirect(url_for('index'))

	return render_template('register.html', form = form)

@app.route('/login', methods = ['GET', 'POST'])
def login():
	form = LoginForm(request.form)
	if request.method == 'POST' and form.validate():
		username = form.username.data
		password_submitted = form.password_submitted.data
		registered_user = User.query.filter_by(username = username).first()
		if registered_user is None:
			#can be changed to reflect the error of incorrect username/password
			flash('No such user exists!', 'danger')
			return redirect(url_for('login'))
		password = registered_user.password
		if sha256_crypt.verify(password_submitted, password):
			session['logged_in'] = True
			session['username'] = username
			flash('Logged in successfully', 'success')
			return redirect(url_for('dashboard'))
		flash('Incorrect Username/Password', 'danger')
		return redirect(url_for('login'))

	return render_template('login.html', form = form)

def logout_auth(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' not in session:
			flash('You have already been logged out!', 'warning')
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return wrap	

@app.route('/logout')
@logout_auth
def logout():
	session.clear()
	flash('You have been logged out', 'success')
	return redirect(url_for('login'))

def session_auth(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' not in session:
			flash('Kindly login to gain access!', 'danger')
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return wrap	

@app.route('/dashboard')
@session_auth
def dashboard():
	form = SearchForm(request.form)
	return render_template('dashboard.html', form = form)

class SearchValidator(object):
	@staticmethod
	def search_default(search_field):
		if search_field == None: return True
		if search_field == '': return True
		if search_field.isspace(): return True 
		return False

@app.route('/search', methods = ['GET', 'POST'])
@app.route('/search/<string:search_field>')
@app.route('/search/<int:page_num>')
@app.route('/search/<string:search_field>/<int:page_num>')
@session_auth
def search(search_field=None, page_num=1):
	form = SearchForm(request.form)
	if request.method == 'POST' and form.validate():
		search_field = form.search_field.data
	if SearchValidator.search_default(search_field):
		search_items = business.objects().paginate(per_page=10, page=page_num, error_out=True)
	else:
		search_items = business.objects(city=search_field).paginate(per_page=10, page=page_num, error_out=True)
	return render_template('dashboard.html', search_items=search_items, search_field=search_field, form = form)

if __name__ == '__main__':
	app.run(debug=True)