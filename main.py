from flask import Flask, jsonify,request, make_response,redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from collections import OrderedDict
import jwt, os, datetime,re
from functools import wraps


"""
    API documentation using Postman 
    URL - https://documenter.getpostman.com/view/19982478/UVsJv6sS
"""

app = Flask(__name__, template_folder='template')
app.config['SECRET_KEY'] = "APIKEY"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'


class User(db.Model):
    """Class to create User object model in sqlite database"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20),nullable=False,unique=True)
    password = db.Column(db.String(80),nullable=False)
    email = db.Column(db.String(30), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)


def token_required(f):
    """Function to verify token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            #print(data['email'])
            current_user = User.query.filter_by(email=data['email'].lower()).first()

        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    """
        method: POST
        Function to create user
    """
    data = request.get_json(force=True)

    if not data and 'name' not in data or 'password' not in data or 'email' not in data:
        return jsonify({'Error':'Invalid Parameter'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')


    if not re.fullmatch(regex,data['email']):
        return jsonify({'Error': 'Invalid email address'})

    user_exists = User.query.filter_by(name=data['name'].upper()).first()
    if not user_exists:
        new_user = User(name=data['name'].upper(), password=hashed_password,email=data['email'].lower())
        db.session.add(new_user)
        db.session.commit()
    else:
        return jsonify({'message':'User already exists'}), 400

    return jsonify({'message': 'New user created!'})

@app.route('/user', methods=['GET'])
@token_required
def get_users(current_user):
    """
        method: GET
        Function to fetch all users
    """
    users = User.query.all()

    output = []

    for user in users:
        user_data = OrderedDict()
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['email'] = user.email
        user_data['last_login'] = user.last_login
        output.append(user_data)


    return jsonify({'Users':output})

@app.route('/user/<id>', methods=['GET'])
@token_required
def get_one_user(current_user,id):
    """
    method: GET
    Function to fetch particulas user based on id
    """
    user = User.query.filter_by(id=id).first()
    if not user:
        return jsonify({"message":"No user found"})

    user_data = OrderedDict()
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['email'] = user.email
    user_data['last_login'] = user.last_login

    return jsonify({'User':user_data})

@app.route('/user/<string:name>', methods=['PUT'])
@token_required
def update(current_user,name):
    """
        method: PUT
        Function to update users based on name
    """
    data = request.get_json()
    if not data :
        return jsonify({'message':'No data to update'})
    elif len(data) > 1:
        return jsonify({'message': 'Too many datas'})
    user_present = User.query.filter_by(name = name.upper()).first()

    if user_present:
        if 'email' in data:
            if not re.fullmatch(regex, data['email']):
                return jsonify({'Error': 'Invalid email address'})
            user_present.email = data['email']

        if 'password' in data:
            user_present.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        db.session.commit()
        return jsonify({'message':'User replaced successfully'})
    else:
        if  'email' in data and 'password' in data:
            new_user = User(name = name.upper(),email=data['email'],
                            password=bcrypt.generate_password_hash(data['password']).decode('utf-8'))
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message':'User created Successfully'})
        else:
            return({'Error':'User does not exits to replace or invalid parameter to create'}), 400

@app.route('/user/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user,id):
    """
        method: DELETE
        Function to delete particular user based on id
    """
    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})

@app.route('/')
def routes():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login():
    """
        method: GET
        Function to generate token by using basic authorization
        username: as same as email address
        Password: <enter password>
    """
    data = request.authorization
    if not re.fullmatch(regex, data['username'].lower()):
        return jsonify({'message': 'Invalid name'})

    user = User.query.filter_by(email=data['username'].lower()).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({'email': data['username'].lower(),
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'], algorithm = 'HS256')

        user.last_login = datetime.datetime.now()

        db.session.commit()
        return jsonify({'token': token})
    else:
        return jsonify({'message':'Invalid password'})

    return jsonify({'message':'Bad request'})


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)