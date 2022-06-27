import jwt
import csv
import io
import numpy as np
import pandas as pd
from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session,
    make_response,
    request,
    jsonify,
    Response
)
from functools import wraps
from datetime import timedelta, datetime
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError
)
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

from app import create_app, db, login_manager, bcrypt
from model import T_user_profile, T_enrollment


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None
        print("getting token")
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=['HS256'])
            current_user = T_user_profile.query\
                .filter_by(email = data['email'])\
                .first()
        except:
            raise
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  func(current_user, *args, **kwargs)
    return decorated

@login_manager.user_loader
def load_user(user_id):
    return T_user_profile.query.get(int(user_id))


app = create_app()


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():
    return render_template("index.html", title="Home")


@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Some input parameters are missing',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )

    user = T_user_profile.query.filter_by(email=auth.get('email')).first()
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
    if check_password_hash(user.pwd, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'email': user.email,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
        return make_response(jsonify({'token': token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )



# Register route
@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():

    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    name, email = data.get('username'), data.get('email')
    password = data.get('password')

    print(name, email, password)
    # checking for existing user
    user = T_user_profile.query \
        .filter_by(email=email) \
        .first()
    if not user:
        # database ORM object
        user = T_user_profile(
            username=name,
            email=email,
            pwd=bcrypt.generate_password_hash(password).decode('utf-8'),
            created_on=datetime.now()
        )
        user.set_password(user.pwd)
        print(user.pwd)
        print(user.username)
        print(user.email)

        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)



@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

#for public
@app.route("/public")
def public():
    return 'For Public'

@app.route('/get_all_enrollments',methods=("GET", "POST"))
@token_required
def get_all_enrollments(current_user):

    page = request.args.get('page', 1 , type=int)
    per_page = request.args.get('per_page', 100, type=int)
    enrollments = T_enrollment.query.paginate(page=page,per_page=per_page)
    output = []
    for enrollment in enrollments.items:
        output.append(
            {
            'mac_address': enrollment.mac_address,
            'user_id' : enrollment.user_id
        }
        )
    meta = {
        'page': enrollments.page,
        'pages': enrollments.per_page,
        'total_count': enrollments.total,
        'prev_page': enrollments.prev_num,
        'next_page': enrollments.next_num,
        'has_next': enrollments.has_next,
        'has_prev': enrollments.has_prev
    }
    return jsonify({'enrollments': output, 'meta': meta})

@app.route('/get_all_users',methods=("GET", "POST"))
@token_required
def get_all_users(current_user):
    users = T_user_profile.query.all()
    output = []
    for user in users:
        output.append(
            {
            'username': user.username,
            'user_id' : user.email,
            'created_on' : user.created_on
        }
        )
    return jsonify({'users': output})

@app.route('/load_csv',methods=["POST"])
@token_required
def load_csv(current_user):
    # Create variable for uploaded file
    csv = pd.read_csv(request.files['csvfile'], delimiter=';',header='infer')
    print(csv.head())
    objects = []
    csv = csv.replace({np.nan: None})

    #convert datetime columns
    csv['enrollmentDateTime'] = pd.to_datetime(csv['enrollmentDateTime'], errors='coerce',format='%d/%m/%Y %H:%M')
    csv['createDate'] = pd.to_datetime(csv['createDate'], errors='coerce', format='%d/%m/%Y %H:%M')
    csv['connectedDateTime'] = pd.to_datetime(csv['connectedDateTime'], errors='coerce',format='%d/%m/%Y %H:%M')
    csv['firstEnrollmentDateTime'] = pd.to_datetime(csv['firstEnrollmentDateTime'],errors='coerce', format='%d/%m/%Y %H:%M')
    csv['disenrollmentDateTime'] = pd.to_datetime(csv['disenrollmentDateTime'], errors='coerce',format='%d/%m/%Y %H:%M')
    csv['lastUpdate'] = pd.to_datetime(csv['lastUpdate'], errors='coerce',format='%d/%m/%Y %H:%M')
    #calling this function again to remove NaT
    csv = csv.replace({np.nan: None})
    #this is an alternative
    #csv.enrollmentDateTime.astype(object).where(csv.enrollmentDateTime.notnull(), None)
    print(csv.head())
    for index, row in csv.iterrows():
        #print('building new enrollment')
        new_enrollment = T_enrollment(
            id=row['id'],
            mac_address=row['macAddress'],
            user_id=row['userId'],
            serial_number=row['serialNumber'],
            status=row['status'],
            enrollment_dtm=row['enrollmentDateTime'],
            create_dtm=row['createDate'],
            connected_dtm=row['connectedDateTime'],
            appliance_model_id=row['applianceModelId'],
            first_enrollment_dtm=row['firstEnrollmentDateTime'],
            disenrollment_dtm=row['disenrollmentDateTime'],
            last_update=row['lastUpdate']
        )
        objects.append(new_enrollment)
        #db.session.add(new_enrollment)
    db.session.bulk_save_objects(objects)
    db.session.commit()

    return make_response('Successfully loaded csv file.', 201)

# Register route
@app.route("/insert_enrollment/", methods=("GET", "POST"), strict_slashes=False)
def insert_enrollment():

    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    mac_address, user_id = data.get('mac_address'), data.get('user_id')
    serial_number = data.get('serial_number')
    status = data.get('status')

    # checking for existing user
    enrollment = T_enrollment.query \
        .filter_by(mac_address=mac_address) \
        .first()
    if not enrollment:
        # database ORM object
        enrollment = T_enrollment(
            mac_address=mac_address,
            user_id=user_id,
            serial_number=serial_number,
            status=status
        )

        # insert user
        db.session.add(enrollment)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('Enrollment already exists.', 202)





if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)