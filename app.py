from flask import request, make_response
from .models import User, Organisation
from . import app, db, bcrypt, secret
from uuid import uuid4
from functools import wraps
import jwt


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
    
    user = User(
        userId = generate_uuid(),
        email = email, 
        firstName = firstName, 
        lastName = lastName, 
        password = hashed_password, 
        phone = phone
    )

    organisation = Organisation(
        orgId = generate_uuid(),
        name = f"{firstName}'s Organisation"
    )
    db.session.add(organisation)

    user.organisations.append(organisation)
    db.session.add(user)

    db.session.commit()

    token = generate_token(user=user)
    return make_response({
        "status": "success",
        "message": "Registration Successful",
        "data": {
            "accessToken": token,
            "user": user.get_user_details()
        }
    }, 201)


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json

    email = data.get('email')
    password = data.get('password')
    
    if not email:
        return make_response({"status": "bad request", "message": "email is a compulsory field"}, 422)
    if not password:
        return make_response({"status": "bad request", "message": "password is a compulsory field"}, 422)
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return make_response({"status": "bad request", "message": "Authentication failed"}, 401)
    
    if not bcrypt.check_password_hash(user.password, password):
        return make_response({"status": "bad request", "message": "Authentication failed"}, 401)

    token = generate_token(user=user)
    return make_response({
        "status": "success",
        "message": "Login successful",
        "data": {
            "accessToken": token,
            "user": user.get_user_details(),
            "orgs": user.get_user_organisations()
        }
    }, 200)


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
            return  make_response({"status": "Server Error", "message": "Error generating user record"}, 500)

    return decorated


@app.route("/", methods=['GET'])
def home():
    return "Welcome to hng-flask-stage-2-app"


@app.route("/api/users/<id>", methods=['GET'])
@check_token_middleware
def user_info(user, id):
    if user.userId ==  id:
        return make_response({
        "status": "success",
        "message": "User Details retrieved successfully",
        "data": {
            "user": user.get_user_details()
        }
    }, 200)
    else:
        return  make_response({"status": "bad request", "message": "User is not authorised to make this request"}, 403)


@app.route("/api/organisations", methods=['GET'])
@check_token_middleware
def get_organisations(user):
    return make_response({
    "status": "success",
    "message": "User Organisations Details Retrieved Successfully",
    "data": {
        "organisations": user.get_user_organisations()
    }
}, 200)


@app.route("/api/organisations/<orgId>", methods=['GET'])
@check_token_middleware
def get_organisation(user, orgId):
    organisations = user.get_user_organisations()
    org = Organisation.query.filter_by(orgId=orgId).first()

    if org.get_organisations_details() in organisations:
        return make_response({
            "status": "success",
            "message": "User Organisations Details Retrieved Successfully",
            "data": org.get_organisations_details()
        }, 200)
    else:
        return make_response({"status": "Not Found", "message": f"organisation with id: {orgId} not Found!"}, 404)


@app.route("/api/organisations", methods=['POST'])
@check_token_middleware
def create_organisation(user):
    data = request.json

    name = data.get('name')
    description = data.get('description')
    
    if not name:
        return make_response({"status": "Bad Request", "message": "name is a compulsory field"}, 400)

    organisation = Organisation(
        orgId = generate_uuid(),
        name = name,
        description = description
    )
    db.session.add(organisation)

    user.organisations.append(organisation)
    db.session.add(user)

    db.session.commit()

    return make_response({
        "status": "success",
        "message": "User Organisations Details Retrieved Successfully",
        "data": organisation.get_organisations_details()
    }, 201)


@app.route("/api/organisations/:orgId/users", methods=['POST'])
def add_user_to_organisation(user, orgId):
    data = request.json

    userId = data.get('name')
    if not userId:
        return make_response({"status": "Bad Request", "message": "name is a compulsory field"}, 400)
    
    user = User.query.filter_by(userId=userId).first()        
    if user == None:
        return  make_response({"status": "bad request", "message": "User Details not Found!"}, 404)

    organisation = Organisation.query.filter_by(orgId=orgId).first()
    if organisation == None:
        return make_response({"status": "Not Found", "message": f"organisation with id: {orgId} not Found!"}, 404)

    organisation.users.append(user)
    db.session.commit()

    return make_response({
        "status": "success",
        "message": "User Added to Organisation Successfully"
    }, 200)


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
    }
    
    token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
    return token


def generate_uuid():
    id = uuid4()
    return str(id)

