from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from sqlalchemy.orm import foreign


# Initialize Flask app
app = Flask(__name__)

# Configuration
# Configure multiple databases using SQLALCHEMY_BINDS:
# - 'users' bind for user information stored in users.db
# - default database for classes and enrollments stored in grades.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grades.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'dev-secret-key'  # Change this in production!
app.config['SECRET_KEY'] = 'another-dev-secret-key'  # For sessions, CSRF, etc.

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

# Models definition

# User model stored in its own DB via bind key
class User(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # Role can be 'student', 'teacher', or 'admin'
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with enrollments - note: foreign key reference to students must be updated
    # If you want to link enrollments to a user in a different database, you may need custom logic.
    enrollments = db.relationship(
        'Enrollment',
        primaryjoin="User.id == foreign(Enrollment.student_id)",
        viewonly=True
    )
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Class model stored in the default grades.db
class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with enrollments
    enrollments = db.relationship('Enrollment', backref='class_obj', lazy=True)
    
    def current_enrollment_count(self):
        return len(self.enrollments)
    
    def is_full(self):
        return self.current_enrollment_count() >= self.capacity
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'capacity': self.capacity,
            'current_enrollment': self.current_enrollment_count(),
            'is_full': self.is_full(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Enrollment model stored in grades.db
class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    # The foreign key reference below assumes that if a Student is stored in users.db, you will handle
    # data consistency. In a production system with separate databases, you might have to manage the relationship differently.
    student_id = db.Column(db.Integer, nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    grade = db.Column(db.String(5), default=None)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'student_id': self.student_id,
            'class_id': self.class_id,
            'grade': self.grade,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Set up Flask-Admin; note that if you wish to administer the users from the separate DB,
# Flask-Admin will need to be configured to handle that bind.
admin = Admin(app, name='Grades App Admin', template_mode='bootstrap3')

class SecureModelView(ModelView):
    def is_accessible(self):
        # In a real app, you would check if the current user is an admin
        # For now, we'll leave it open for simplicity
        return True
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

# Add model views
# For the user model, Flask-Admin will automatically use the correct bind based on __bind_key__
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Class, db.session))
admin.add_view(SecureModelView(Enrollment, db.session))

# Create templates folder if it doesn't exist
os.makedirs('templates', exist_ok=True)

# API Routes

@app.route('/api/users/register', methods=['POST'])
def api_register():
    data = request.get_json()
    
    # Check required fields
    if not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists (querying the separate bind for users)
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 400
    
    # Create new user. Role is read from the post data; default is 'student'
    new_user = User(
        name=data['name'],
        email=data['email'],
        role=data.get('role', 'student')
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    access_token = create_access_token(identity=new_user.id)
    
    return jsonify({
        'message': 'User registered successfully',
        'user': new_user.to_dict(),
        'token': access_token
    }), 201

@app.route('/api/users/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    if not all(k in data for k in ['email', 'password']):
        return jsonify({'message': 'Missing email or password'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'Login successful',
        'user': user.to_dict(),
        'token': access_token
    }), 200

# Web routes for frontend

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid email or password'
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            error = 'Email already registered'
        else:
            # Here, you could also allow role selection if needed,
            # but be cautious with allowing users to self-assign higher roles.
            new_user = User(name=name, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    
    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    classes = Class.query.all()
    return render_template('dashboard.html', classes=classes)

# Create both databases. When using binds, you must specify the bind key for the models.
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
