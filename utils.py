from uuid import uuid4
from functools import wraps
import jwt
from datetime import datetime, timedelta
from init_app import bcrypt, secret
from flask import request, make_response
from models import User


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
        "name": f"{user.firstName} {user.lastName}",
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    
    token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
    return token


def generate_uuid():
    id = uuid4()
    return str(id)


def check_token_middleware(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token == None:
            return  make_response({"status": "bad request", "message": "Missing Token"}, 401)
        if not token.startswith('Bearer '):
            return  make_response({"status": "bad request", "message": "Invalid Token"}, 401)
        token = token[7::]

        try:
            data = jwt.decode(token, secret, algorithms=['HS256'])
            userId = data['id']
            user = User.query.filter_by(userId=userId).first()
            
            if user == None:
                return  make_response({"status": "bad request", "message": "User Details not Found!"}, 404)
            return func(user, *args, **kwargs)
        except Exception as e:
            return  make_response({"status": "bad request", "message": "Invalid Token"}, 401)

    return decorated


def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

