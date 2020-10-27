from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)

    # Sets information for the new user
    def __init__(self, fname, lname, email, password):
        self.firstname = fname
        self.lastname = lname
        self.email = email
        self.password = password

    # Creates a list representation of the task object
    def to_list(self):
        return [self.id, self.firstname, self.lastname, self.email]
    
    def to_json(self):
        return jsonify({
            'id': self.id,
            'firstName':self.firstname,
            'lastName':self.lastname,
            'email':self.email
        })
