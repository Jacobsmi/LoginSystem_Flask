from flask import Flask
from dotenv import load_dotenv
from flask_cors import CORS

import os

load_dotenv()

app = Flask(__name__)

CORS(app, supports_credentials=True)

# put database credentials in the app's constant
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# put JWT credentials in app's constant
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SEC')