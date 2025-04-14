from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Flask-Admin imports
from flask_admin import Admin, AdminIndexView, BaseView, expose
from flask_admin.contrib.sqla import ModelView
from sqlalchemy.orm import foreign

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grades.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'dev-secret-key'
app.config['SECRET_KEY'] = 'another-dev-secret-key'

# Initialize Extensions
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

class User(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Establish a read-only relationship with enrollments.
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
        
class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    
class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=30)
    teacher_id = db.Column(db.Integer, nullable=True)  # No foreign key constraint for flexibility
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    enrollments = db.relationship('Enrollment', backref='class_obj', lazy=True)
    
    def current_enrollment_count(self):
        return len(self.enrollments)
    
    def is_full(self):
        return self.current_enrollment_count() >= self.capacity

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    grade = db.Column(db.String(5), default=None)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/create_class', methods=['GET', 'POST'])
def create_class():
    if request.method == 'POST':
        class_name = request.form.get('class_name')
        teacher_name = request.form.get('teacher_name')

        # Look up the teacher by name (make sure teacher names are unique or handle duplicates)
        teacher = Teacher.query.filter_by(name=teacher_name).first()
        if not teacher:
            flash('Teacher not found. Please check the name and try again.', 'error')
            return redirect(url_for('create_class'))

        # Now create a new class with that teacher
        new_class = Class(name=class_name, teacher=teacher)
        db.session.add(new_class)
        db.session.commit()

        flash('Class created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_class.html')

# ClearDatabaseView: Provides an interface to clear all data.
class ClearDatabaseView(BaseView):
    @expose('/')
    def index(self):
        # Render a confirmation page for clearing the database.
        return self.render('clear_database.html')
    
    @expose('/clear', methods=['POST'])
    def clear(self):
        try:
            # Clear enrollments and classes.
            db.session.query(Enrollment).delete()
            db.session.query(Class).delete()
            # For the user database, drop and recreate tables.
            user_engine = db.get_engine(app, bind='users')
            User.metadata.drop_all(user_engine)
            User.metadata.create_all(user_engine)
            db.session.commit()
            flash("All data has been deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error deleting data: " + str(e), "error")
        return redirect(url_for('.index'))

# Custom Admin Index View: Only accessible to admin users.
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        # Ensure that only an admin (as per session) can access admin pages.
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

# SecureModelView: Secures model views for admin access.
class SecureModelView(ModelView):
    def is_accessible(self):
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

# Initialize Flask-Admin
admin = Admin(app,
              name='Grades App Admin',
              template_mode='bootstrap3',
              index_view=MyAdminIndexView())

# Register models with Flask-Admin.
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Class, db.session))
admin.add_view(SecureModelView(Enrollment, db.session))
admin.add_view(ClearDatabaseView(name='Clear DB', endpoint='cleardb'))

os.makedirs('templates', exist_ok=True)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('role', None)
    session.pop('email', None)
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
            session['email'] = user.email
            if user.role == 'student':
                return redirect(url_for('student'))
            elif user.role == 'teacher':
                return redirect(url_for('teacher'))
            elif user.role == 'admin':
                return redirect(url_for('admin.index'))  # Corrected endpoint
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

@app.route('/student')
def student():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    enrolled_classes = []
    if user:
        enrollments = Enrollment.query.filter_by(student_id=user.id).all()
        enrolled_classes = [Class.query.get(e.class_id) for e in enrollments]
    classes = Class.query.all()
    return render_template('student.html', user=user, classes=classes, enrolled_classes=enrolled_classes)

# Enroll a student into a class.
@app.route('/enroll/<int:class_id>', methods=['POST'])
def enroll(class_id):
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.is_full():
        flash('Class is full!', 'error')
        return redirect(url_for('student'))
    if Enrollment.query.filter_by(student_id=user.id, class_id=class_id).first():
        flash('You are already enrolled in this class!', 'error')
        return redirect(url_for('student'))
    enrollment = Enrollment(student_id=user.id, class_id=class_id)
    db.session.add(enrollment)
    db.session.commit()
    flash('Successfully enrolled!', 'success')
    return redirect(url_for('student'))

@app.route('/teacher')
def teacher():
    if 'role' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    classes = Class.query.filter_by(teacher_id=user.id).all()
    class_students = {}
    for c in classes:
        enrollments = Enrollment.query.filter_by(class_id=c.id).all()
        students = []
        for e in enrollments:
            student = User.query.get(e.student_id)
            students.append({'name': student.name, 'email': student.email, 'grade': e.grade, 'enrollment_id': e.id})
        class_students[c.id] = students
    return render_template('teacher.html', user=user, classes=classes, class_students=class_students)

# Edit a student's grade (Teacher only).
@app.route('/edit_grade/<int:enrollment_id>', methods=['POST'])
def edit_grade(enrollment_id):
    if 'role' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    enrollment = Enrollment.query.get_or_404(enrollment_id)
    class_obj = Class.query.get_or_404(enrollment.class_id)
    user = User.query.filter_by(email=session['email']).first()
    if class_obj.teacher_id != user.id:
        flash('Unauthorized access!', 'error')
        return redirect(url_for('teacher'))
    grade = request.form.get('grade')
    if grade in ['A', 'B', 'C', 'D', 'F', '']:
        enrollment.grade = grade or None
        db.session.commit()
        flash('Grade updated!', 'success')
    else:
        flash('Invalid grade! Use A, B, C, D, F, or leave blank.', 'error')
    return redirect(url_for('teacher'))

# Admin Dashboard route: For now, simply renders the admin template.
@app.route('/admin')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin.html')

with app.app_context():
    db.drop_all()
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
