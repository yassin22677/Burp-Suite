from flask import Blueprint, render_template, request, redirect, url_for

# Create Blueprint
auth_bp = Blueprint('auth_bp', __name__)

# 🏠 Home route (Login page)
@auth_bp.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Dummy login (for now)
        if username == 'admin' and password == '1234':
            return redirect(url_for('auth_bp.dashboard'))
        else:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)

    return render_template('login.html')

# 📊 Dashboard route
@auth_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
