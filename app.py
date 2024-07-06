from flask import request, make_response
from .models import User, Organisation
from . import app, db, bcrypt, secret
from uuid import uuid4
from datetime import datetime
import jwt


@app.route("/", methods=['GET'])
def home():
    return "Welcome to hng-flask-stage-2-app"


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    
    firstName: str = data.get('firstName')
    lastName = data.get('lastName')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    errors_list = []

    # Input Validations
    if not firstName:
        add_error_to_list(list=errors_list, field="firstName", message="firstName is a compulsory field")
    if firstName.isspace() or firstName == "":
        add_error_to_list(list=errors_list, field="firstName", message="firstName cannot be blank")

    if not lastName:
        add_error_to_list(list=errors_list, field="lastName", message="lastName is a compulsory field")

    if not email:
        add_error_to_list(list=errors_list, field="email", message="email is a compulsory field")

    if not password:
        add_error_to_list(list=errors_list, field="password", message="password is a compulsory field")

    user = User.query.filter_by(email=email).first()
    if user:
        add_error_to_list(list=errors_list, field="email", message="Email Address already in use")

    if len(errors_list) != 0:
        return make_response(
            {"errors": errors_list}, 
            422
        )

    # hash password
    # hashed_password = generate_password_hash(password)
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    id = uuid4()

    user = User(
        userId = str(id),
        email = email, 
        firstName = firstName, 
        lastName = lastName, 
        password = hashed_password, 
        phone = phone
    )

    db.session.add(user)
    db.session.commit()

    # token = generate_token(userId=user.userId)
    token = generate_token(user=user)
    return make_response({
        "status": "success",
        "message": "Registration Successful",
        "data": {
            "accessToken": token,
            "user": user.get_user()
        }
    }, 201)


@app.route('/auth/login')
def login():
    data = request.json

    email = data.get('email')
    password = data.get('password')
    
    if not email:
        return make_response({"message": "email is a compulsory field"}, 400)
    if not password:
        return make_response({"message": "password is a compulsory field"}, 400)
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return make_response({"status": "bad request", "message": "Authentication failed"}, 401)
    
    if not bcrypt.check_password_hash(user.password, password):
        return make_response({"status": "bad request", "message": "Authentication failed"}, 401)
    
    token = generate_token(user=user)
    return make_response()
        

def add_error_to_list(list, field, message):
    error = {"field": field, "message": message}
    list.append(error)


def generate_token(user):
    header = {  
        "alg": "HS256",  
        "typ": "JWT"  
    }  
    
    payload = {  
        "id": user.userId,  
        "name": f"{user.firstName} {user.lastName}"
        # "iat": 1516239022
    }
    
    token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
    print(type(token))
    print(f"{token=}")
    return token


@app.route('/api/users/<id>')
def get_user_details():
    pass
