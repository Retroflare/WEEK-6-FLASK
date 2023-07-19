from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))    
    username = db.Column(db.String(80), nullable = False, unique = True)
    email = db.Column(db.String(150), nullable = False, unique = True)
    password_hash = db.Column(db.String(), nullable = False)    
    posts = db.relationship('Post', backref = 'author', lazy=True)

    def __repr__(self):
        return f'<USER: {self.username}>'
    
    def commit(self):
        db.session.add(self)
        db.session.commit()

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    post_id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(), nullable = False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable = False)

    def __repr__(self):
        return f'<Post: {self.body}>'
    
    def commit(self):
        db.session.add(self)
        db.session.commit()