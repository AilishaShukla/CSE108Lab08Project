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
from wtforms import fields
from flask import redirect, url_for

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
    id = db.Column(db.Integer, primary_key=True, autoincrement=False)
    name = db.Column(db.String(100), unique=True, nullable=False)
    
class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=30)
    teacher_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    enrollments = db.relationship('Enrollment', backref='class_obj', lazy=True)
    
    def current_enrollment_count(self):
        return len(self.enrollments)
    
    def is_full(self):
        return self.current_enrollment_count() >= self.capacity

# --- Modified Enrollment Model ---
class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)

    grade = db.Column(db.Float, default=None)  # Changed from String to Float for numeric grades

    grade = db.Column(db.Integer, nullable=True)  # Changed to Integer for numerical grades (0-100)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/create_class', methods=['GET', 'POST'])
def create_class():
    if request.method == 'POST':
        class_name = request.form.get('class_name')
        teacher_name = request.form.get('teacher_name')
        teacher = Teacher.query.filter_by(name=teacher_name).first()
        if not teacher:
            flash('Teacher not found. Please check the name and try again.', 'error')
            return redirect(url_for('create_class'))
        new_class = Class(name=class_name, teacher_id=teacher.id)
        db.session.add(new_class)
        db.session.commit()
        flash('Class created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_class.html')

class ClearDatabaseView(BaseView):
    @expose('/')
    def index(self):
        flash("Use the inline clear database form on the Admin Dashboard.", "info")
        return redirect(url_for('admin.index'))


    @expose('/clear', methods=['POST'])
    def clear(self):
        try:
            db.session.query(Enrollment).delete()
            db.session.query(Class).delete()
            user_engine = db.get_engine(app, bind='users')
            User.metadata.drop_all(user_engine)
            User.metadata.create_all(user_engine)
            db.session.commit()
            flash("All data has been deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error deleting data: " + str(e), "error")
        return redirect(url_for('.index'))

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return session.get('role') == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))
    
class SecureModelView(ModelView):
    def is_accessible(self):
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

class UserView(ModelView):
    def is_accessible(self):
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))
    
    form_columns = ['name', 'email', 'password_hash', 'role']
    form_excluded_columns = ['created_at']
    form_overrides = {
        'password_hash': fields.StringField,
    }

class EnrollmentView(ModelView):
    def is_accessible(self):
        return session.get('role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))
    
    form_columns = ['student_id', 'class_id', 'grade']
    form_excluded_columns = ['created_at']

# Initialize Flask-Admin
admin = Admin(app, name='Grades App Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(UserView(User, db.session))
admin.add_view(SecureModelView(Class, db.session))
admin.add_view(EnrollmentView(Enrollment, db.session))
admin.add_view(ClearDatabaseView(name='Clear DB', endpoint='cleardb'))

os.makedirs('templates', exist_ok=True)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
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
                return redirect(url_for('admin.index'))
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
            # Create a new user
            new_user = User(name=name, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            # If registering as a teacher, also create a teacher record
            if role == 'teacher':
                teacher = Teacher(id=new_user.id, name=new_user.name)
                db.session.add(teacher)
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
    
    if role == 'teacher':
        teacher = Teacher(id=new_user.id, name=new_user.name)
        db.session.add(teacher)
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
        for enrollment in enrollments:
            class_obj = Class.query.get(enrollment.class_id)
            enrolled_classes.append({
                "class": class_obj,
                "grade": enrollment.grade,
                "enrollment_id": enrollment.id,
            })
    classes = Class.query.all()
    return render_template('student.html', user=user, classes=classes, enrolled_classes=enrolled_classes)

@app.route('/remove_enrollment/<int:enrollment_id>', methods=['POST'])
def remove_enrollment(enrollment_id):
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    enrollment = Enrollment.query.get_or_404(enrollment_id)
    user = User.query.filter_by(email=session['email']).first()
    # Ensure the enrollment belongs to the logged-in student
    if enrollment.student_id != user.id:
        flash("Unauthorized access!", "error")
        return redirect(url_for('student'))
    db.session.delete(enrollment)
    db.session.commit()
    flash("Course removed successfully!", "success")
    return redirect(url_for('student'))

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
    # Retrieve teacher record using the same user id
    teacher = Teacher.query.get(user.id)
    classes = Class.query.filter_by(teacher_id=user.id).all()
    class_students = {}
    for c in classes:
        enrollments = Enrollment.query.filter_by(class_id=c.id).all()
        students = []
        for e in enrollments:
            student = User.query.get(e.student_id)
            students.append({'name': student.name, 'email': student.email, 'grade': e.grade, 'enrollment_id': e.id})
        class_students[c.id] = students
    return render_template('teacher.html', user=user, teacher=teacher, classes=classes, class_students=class_students)

# --- Modified Edit Grade Route ---
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

    
    grade_input = request.form.get('grade')
    if grade_input == '':
        # Allow clearing the grade
        enrollment.grade = None
    else:
        try:
            numeric_grade = float(grade_input)
            # Validate the grade range (for example, 0-100)
            if 0 <= numeric_grade <= 100:
                enrollment.grade = numeric_grade
            else:
                flash('Invalid grade! Enter a number between 0 and 100.', 'error')
                return redirect(url_for('teacher'))
        except ValueError:
            flash('Invalid grade! Please enter a valid number.', 'error')
            return redirect(url_for('teacher'))
    
    db.session.commit()
    flash('Grade updated!', 'success')

    grade = request.form.get('grade')
    if grade == '':
        enrollment.grade = None
        db.session.commit()
        flash('Grade updated!', 'success')
    else:
        try:
            grade = int(grade)
            if 0 <= grade <= 100:
                enrollment.grade = grade
                db.session.commit()
                flash('Grade updated!', 'success')
            else:
                flash('Invalid grade! Grade must be between 0 and 100.', 'error')
        except ValueError:
            flash('Invalid grade! Grade must be a number between 0 and 100 or left blank.', 'error')

    return redirect(url_for('teacher'))

@app.route('/admin')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin.html')

# Initialize the database without dropping existing tables
with app.app_context():
    # Removed db.drop_all() to preserve data between restarts
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
