#BASIC FLASK APP IMPORTS
from flask import Flask,request,redirect,render_template,flash,jsonify,url_for,make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import os
import json

#GOOGLE AUTHENTICATION IMPORTS $ SQLITE

import sqlite3
from flask_login import LoginManager,current_user,login_required,login_user,logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests
from decouple import config

from db import init_db_command
from user import User

app=Flask(__name__)

#JWT IMPORTS $ SQLALCHEMY

# import uuid
# from werkzeug.security import generate_password_hash,check_password_hash
# import jwt
# from datetime import datetime, timedelta
# from functools import wraps
# from flask_sqlalchemy import SQLAlchemy
# from functools import wraps

# app.config['SECRET_KEY'] = 'project'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# db=SQLAlchemy(app)


UPLOADS = 'static/image-uploads/'
#CONFIGS
app.config['UPLOADS']=UPLOADS
app.secret_key="project"
ext_list=['jpg','png','jpeg','.tif','.tiff','.gif','.eps','.bmp']


def check(name):
	return '.' in name and name.rsplit('.', 1)[1].lower() in ext_list
 
# class User(db.Model):
# 	id=db.Column(db.Integer,primary_key=True)
# 	user_id=db.Column(db.String(70))
# 	name=db.Column(db.String(50),nullable=False)
# 	email=db.Column(db.String(50),unique=True,nullable=False)
# 	password=db.Column(db.String(50),nullable=False)



								# GOOGLE AUTH STUFF

#GOOGLE AUTH CONFIGS


GOOGLE_CLIENT_ID=config('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET=config('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = (
	"https://accounts.google.com/.well-known/openid-configuration"
)

login_manager=LoginManager()
login_manager.init_app(app)

# try:
# 	init_db_command()
# except sqlite3.OperationalError:
# 	pass

client=WebApplicationClient(GOOGLE_CLIENT_ID)

@login_manager.user_loader
def load_user(user_id):
	return User.get(user_id)

@app.route('/')
def index():
	if current_user.is_authenticated:
		return render_template('home.html')


	else:
		return render_template('auth.html')


def get_google_provider_cfg():
	try:
		return requests.get(GOOGLE_DISCOVERY_URL).json()
	except:
		pass

@app.route("/login")
def login():
	google_provider_cfg = get_google_provider_cfg()
	authorization_endpoint = google_provider_cfg["authorization_endpoint"]

	request_uri = client.prepare_request_uri(
		authorization_endpoint,
		redirect_uri="https://127.0.0.1:5000/login/callback",
		scope=["openid", "email", "profile"],
	)
	print(request.base_url)
	return redirect(request_uri)


@app.route("/login/callback")
def callback():
	code = request.args.get("code")

	google_provider_cfg = get_google_provider_cfg()
	token_endpoint = google_provider_cfg["token_endpoint"]

	token_url, headers, body = client.prepare_token_request(
	    token_endpoint,
	    authorization_response=request.url,
	    redirect_url=request.base_url,
	    code=code
	)
	token_response = requests.post(
		token_url,
		headers=headers,
		data=body,
		auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
	)

	client.parse_request_body_response(json.dumps(token_response.json()))


	userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
	uri, headers, body = client.add_token(userinfo_endpoint)
	userinfo_response = requests.get(uri, headers=headers, data=body)

	if userinfo_response.json().get("email_verified"):
		unique_id = userinfo_response.json()["sub"]
		users_email = userinfo_response.json()["email"]
		picture = userinfo_response.json()["picture"]
		users_name = userinfo_response.json()["given_name"]
	else:
		return "User email not available or not verified by Google.", 400


	user = User(
	    id_=unique_id, name=users_name, email=users_email, profile_pic=picture
	)

	if not User.get(unique_id):
		User.create(unique_id, users_name, users_email, picture)

	login_user(user)

	return redirect(url_for("index"))



@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect(url_for("index"))








						#THROTTLE LIMIT TO API STUFF

#DEFAULT DECORATOR LIMITS
#INITIALISING A DECORATOR

# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )







# @app.route('/register',methods=["POST"])
# def register_auth():
# 	name = request.form.get('name')
# 	email = request.form.get('email')
# 	password = request.form.get('password')

# 	user = User.query.filter_by(email=email).first()

# 	if not user:
# 		user = User(
# 				user_id=str(uuid.uuid4()),
# 				name=name,
# 				email=email,
# 				password=generate_password_hash(password)
# 			)
# 		db.session.add(user)
# 		db.session.commit()

# 		# return jsonify({'msg':'Successfully Registered'}),200
# 		return redirect(url_for('login'))

# 	else:
# 		# return jsonify({'msg':'User already Exists.Try Again!!'}),401
# 		flash('User already exists!!!')
# 		return redirect(url_for('register'))




# @app.route('/login',methods=["POST"])
# def login_auth():

# 	email = request.form.get('email')
# 	password=request.form.get('password')


# 	if not password or not email:
# 		return jsonify({"msg":"Fill all the details"}),400

# 	user = User.query.filter_by(email=email).first()

# 	if not user:
# 		return jsonify({"msg":"User not found.Register!!"}),400

# 	if check_password_hash(user.password,password):
# 		token=jwt.encode({
# 			'user_id':user.user_id,
# 			'exp':datetime.utcnow()+timedelta(minutes=30)
# 			},app.config['SECRET_KEY'])

# 		return jsonify({'token':token}),200

# 	return jsonify({'msg':'Enter correct credentials!!'}),401


# def verify_token(f):
# 	@wraps(f)
# 	def decorated(*args,**kwargs):
# 		token=None

# 		if 'x-access-token' in request.headers:
# 			token=request.headers['x-access-token']

# 		if not token:
# 			return jsonify({'msg':'No token found!!'}),400
# 		try:
# 			data=jwt.decode(token,app.config['SECRET_KEY'],algorithms=["HS256"])
# 			user = User.query.filter_by(user_id=data['user_id']).first()
# 		except:
# 			return jsonify({'msg':'Invalid Token!!!'}),401

# 		return f(user,*args,**kwargs)

# 	return decorated





# @app.route('/dummy')
# @verify_token
# def dummy(user):
# 	return jsonify({'msg':'Hello'})

						#BASIC APP STUFF	


@app.route('/')
# @verify_token
def home():
	return render_template('home.html')



						# # FILE UPLOAD FUNCTIONALITY
@app.route('/display',methods=["GET","POST"])

# #RATE LIMITTING DECORATOR
# # @limiter.limit("5 per minute")		
def upload():
	
	if request.method == 'POST':
		img = request.files['img']
		if img.filename == '':
			flash('No Image Uploaded')
			return redirect('/')

		elif img and check(img.filename):
			name = secure_filename(img.filename)
			if os.path.isfile('./static/image-uploads/{img.filename}')==False:
				img.save(os.path.join(app.config['UPLOADS'],name))
			if request.form.get('name'):
				return render_template('name.html',name=name)
			elif request.form.get('image'):
				return render_template('image.html',name=name)

		else:
			flash("Invalid Extension Selected")
			return redirect('/')

	session.pop('_flashes',None)

#SHOW IMAGE
@app.route('/display/<name>')
def display_image(name):
	return redirect(url_for('static', filename='image-uploads/' + name), code=301)


if __name__=="__main__":
	app.run(debug=True,ssl_context="adhoc")

# ,ssl_context="adhoc"