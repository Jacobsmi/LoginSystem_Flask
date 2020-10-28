# Import necessary libraries
import sys

from flask import  request, jsonify
from flask import json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from psycopg2.errors import UniqueViolation
import bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    create_refresh_token, get_jwt_identity
)

from config import app
from models import db, User

db.init_app(app)
jwt = JWTManager(app)

# Route to create a new user 
@app.route('/createuser', methods=['POST'])
def create_user():
    # Attempts to add new users to the database
    print(request.get_json())
    try:
        # Get the info sent in the POST request
        user_info=request.get_json()
        # hashed password
        password = user_info['pass'].encode('utf-8')
        pass_hash = bcrypt.hashpw(password, bcrypt.gensalt())
        pass_hash_decoded = pass_hash.decode('utf8')
        # Create a new User object with the given info
        new_user = User(user_info['fname'], user_info['lname'], user_info['email'], pass_hash_decoded)
        # Stage adding the new user to the database
        db.session.add(new_user)
        # Commit the staged changes
        db.session.commit()
        # Create a JWT for the new user
        access_token = create_access_token(identity=new_user.id)
        refresh_token_cookie = ('refresh_token='+ create_refresh_token(identity=new_user.id))
        # {Set-Cookie: refresh_token=tokenvalue;}
        return jsonify({
            'access_token': create_access_token(identity=new_user.id)
        }), 200, {'Set-Cookie': f'{refresh_token_cookie}; SameSite=Lax; HttpOnly'}
    
    # Excepts missing key errors
    except KeyError as e:
        # Turn error into a string 
        error_str = str(e)
        # Create an error string based on the missing field
        error = 'missing_attribute_'+error_str.translate({ord("'"): None})
        # return error string with missing field
        return jsonify({
            'status':'failure',
            'error': error
        }), 200

    # Excepts non-unique or invalid information errors
    except exc.IntegrityError as e:
        # If non-unique find the key that was non-unique and return
        if isinstance(e.orig, UniqueViolation):
            if 'users_email_key' in str(e.orig):
                return jsonify({
                    'status':'failure',
                    'error':'duplicate_email'
                }), 200
            else: 
                return jsonify({
                    'status':'failure',
                    'error':'duplicate_other'
                }), 200
    
    return jsonify({
        'status':'failure',
        'error':'unknown_error'
    }), 200


# Login Route
@app.route('/login', methods=['POST'])
def login():
    # Get the user info
    user_info = request.get_json()
    print(user_info['email'])
    result = db.session.query(User).filter(User.email == user_info['email']).first()
    if( result == None):
        print("No user with that email")
    else:
        # Encoded the strings with utf-8
        encoded_pass = user_info['pass'].encode('utf-8')
        encoded_result_pass = result.password.encode('utf-8')
        # Check if the supplied password could be hashed to the stored password
        if bcrypt.checkpw(encoded_pass, encoded_result_pass):
            access_token = create_access_token(identity=result.id)
            refresh_token_cookie = ('refresh_token='+ create_refresh_token(identity=result.id))
            # {Set-Cookie: refresh_token=tokenvalue;}
            return jsonify({
                'access_token': create_access_token(identity=result.id)
            }), 200, {'Set-Cookie': f'{refresh_token_cookie}; SameSite=Lax; HttpOnly'}
        else: 
            return jsonify(error='wrong_pass')
        print(result)
    
    return jsonify(test='test'), 200

@app.route('/basicuserinfo', methods=['GET'])
@jwt_required
def get_basic_user_info():
    try:
        # Access the identity of the current user with get_jwt_identity
        current_user = get_jwt_identity()
        print(f"Current User is {current_user}")
        # Query the database for the user info
        user_object = db.session.query(User).get(current_user)
        print(user_object.to_json())
        return user_object.to_json(), 200
    except:
        return jsonify(error='error'), 200       

if len(sys.argv) > 1:
    if sys.argv[1].lower() == 'migrate' or sys.argv[1].lower() == 'm':
        with app.app_context():
            db.create_all()
    elif sys.argv[1].lower == 'demigrate' or sys.argv[1].lower() == 'd':
        with app.app_context():
            db.drop_all()
else:
    app.run(debug=True)