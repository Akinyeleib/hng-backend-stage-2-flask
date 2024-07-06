from flask import Flask
from dotenv import load_dotenv
from os import getenv as env
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt 

load_dotenv()

app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app) 


app.config['SQLALCHEMY_DATABASE_URI'] = env("LOCAL_DB")
secret = env("JWT_SECRET")

db.init_app(app)
