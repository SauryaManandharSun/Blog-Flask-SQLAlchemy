from flask import render_template, redirect, url_for, request, flash, abort
from flask_login import login_user, login_required, logout_user, current_user
from models import db, User, BlogPost
from flask_bcrypt import Bcrypt
from flask import Blueprint

bcrypt = Bcrypt()

routes = Blueprint('routes', __name__)

@routes.route('/')
def home():
    return redirect(url_for('routes.login'))

@routes.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('routes.register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('routes.register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('routes.login'))

    return render_template('register.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('routes.dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
            return redirect(url_for('routes.login'))

    return render_template('login.html')

@routes.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    posts = BlogPost.query.order_by(BlogPost.id.desc()).paginate(page=page, per_page=5)
    return render_template('dashboard.html', posts=posts)

@routes.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        post = BlogPost(title=title, content=content, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Post created!', 'success')
        return redirect(url_for('routes.dashboard'))
    return render_template('create_post.html')

@routes.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        db.session.commit()
        flash('Post updated!', 'success')
        return redirect(url_for('routes.dashboard'))
    return render_template('edit_post.html', post=post)

@routes.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted!', 'info')
    return redirect(url_for('routes.dashboard'))

@routes.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))

@routes.app_errorhandler(403)
def forbidden_error(error):
    return render_template('not_allowed.html'), 403
