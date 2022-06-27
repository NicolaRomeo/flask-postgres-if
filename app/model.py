from app import db, bcrypt
import app
from flask_login import UserMixin
import jwt
import datetime


class T_user_profile(UserMixin, db.Model):
    __tablename__ = "user_profile"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    pwd = db.Column(db.String(300), nullable=False)
    created_on = db.Column(db.DateTime, unique=True)

    def get_id(self):
        return (self.user_id)
    #only used for postgres
    def set_password(self, pw):
        self.password = bcrypt.generate_password_hash(pw).decode('utf-8')


    def __repr__(self):
        return '<User %r>' % self.username

class T_enrollment(UserMixin, db.Model):
    __tablename__ = "enrollment"

    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    serial_number = db.Column(db.Integer)
    status = db.Column(db.Integer)
    enrollment_dtm = db.Column(db.DateTime)
    create_dtm = db.Column(db.DateTime)
    connected_dtm = db.Column(db.DateTime)
    appliance_model_id = db.Column(db.Integer)
    first_enrollment_dtm = db.Column(db.DateTime)
    disenrollment_dtm = db.Column(db.DateTime)
    last_update = db.Column(db.DateTime)

    def get_id(self):
        return (self.id)


