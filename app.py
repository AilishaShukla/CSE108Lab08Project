from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from sqlalchemy.orm import foreign
from flask_admin import BaseView, expose
from flask import flash, redirect, url_for

# Initialize Flask app
app = Flask(__name__)

# Configuration for multiple databases
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grades.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'dev-secret-key'
app.config['SECRET_KEY'] = 'another-dev-secret-key'

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

class ClearDatabaseView(BaseView):
    @expose('/')
    def index(self):
        # Render a template with a button to clear the database
        return self.render('clear_database.html')
    
    @expose('/clear', methods=['POST'])
    def clear(self):
        try:
            # Delete records from Enrollment and Class tables
            db.session.query(Enrollment).delete()
            db.session.query(Class).delete()
            
            # For the User model (stored in a separate bind), drop and recreate the table
            user_engine = db.get_engine(app, bind='users')
            User.metadata.drop_all(user_engine)
            User.metadata.create_all(user_engine)
            db.session.commit()
            flash("All data has been deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error deleting data: " + str(e), "error")
        return redirect(url_for('.index'))
    
# Custom admin index view restricting access to admin users
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

# Custom ModelView for admin-only access
class SecureModelView(ModelView):
    def is_accessible(self):
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

# User model (stored in users.db)
class User(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
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

# Class model (stored in grades.db)
class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
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

# Enrollment model (stored in grades.db)
class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
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

# Initialize Flask-Admin (using one instance only)
# Initialize Flask-Admin with custom index view for admins.
admin = Admin(app, name='Grades App Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())

# Add secure model views for CRUD operations.
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Class, db.session))
admin.add_view(SecureModelView(Enrollment, db.session))

# Add custom Clear Database view.
admin.add_view(ClearDatabaseView(name='Clear DB', endpoint='cleardb'))



# Create templates folder if it doesn't exist
os.makedirs('templates', exist_ok=True)

# API Routes (registration and login endpoints)
@app.route('/api/users/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 400
    
    role = data.get('role', 'student')
    if role not in ['student', 'teacher', 'admin']:
        role = 'student'
    
    new_user = User(name=data['name'], email=data['email'], role=role)
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
            session['role'] = user.role
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
        role = request.form.get('role', 'student')
        if role not in ['student', 'teacher', 'admin']:
            role = 'student'
        
        if User.query.filter_by(email=email).first():
            error = 'Email already registered'
        else:
            new_user = User(name=name, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    
    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    classes = Class.query.all()
    return render_template('dashboard.html', classes=classes)

# Create databases and tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
    