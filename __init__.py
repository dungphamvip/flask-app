from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from dotenv import load_dotenv
import logging
from datetime import datetime, timedelta
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import json
import socket
from flask_mail import Mail, Message
import secrets
import csv
import io
from requests_oauthlib import OAuth2Session

# Cho phép HTTP trong môi trường phát triển
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Load biến môi trường
load_dotenv()

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Khởi tạo URL cho ứng dụng
BASE_URL = os.getenv('BASE_URL', 'http://localhost:80')
PUBLIC_URL = os.getenv('PUBLIC_URL', BASE_URL)
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

# Khởi tạo các extension
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Cấu hình Google OAuth
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_SCOPES = ["openid", "email", "profile"]

def get_google_provider_cfg():
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except Exception as e:
        app.logger.error(f"Error fetching Google provider config: {e}")
        return None

@app.route('/google/login')
def google_login():
    try:
        # Lấy cấu hình từ Google
        google_provider_cfg = get_google_provider_cfg()
        if not google_provider_cfg:
            raise Exception("Could not fetch Google provider config")

        # Tạo flow
        client = OAuth2Session(
            GOOGLE_CLIENT_ID,
            scope=GOOGLE_SCOPES,
            redirect_uri=f"{PUBLIC_URL}/google/callback"
        )

        # Tạo URL authorization
        authorization_url, state = client.authorization_url(
            google_provider_cfg["authorization_endpoint"],
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true"
        )

        # Lưu state
        session["oauth_state"] = state
        
        app.logger.info(f"Starting OAuth flow. Auth URL: {authorization_url}")
        return redirect(authorization_url)

    except Exception as e:
        app.logger.error(f"Error in Google login: {e}")
        flash("Có lỗi xảy ra khi kết nối với Google", "error")
        return redirect(url_for("login"))

@app.route('/google/callback')
def google_callback():
    try:
        # Verify state
        if "oauth_state" not in session:
            raise Exception("Missing OAuth state")

        # Lấy cấu hình từ Google
        google_provider_cfg = get_google_provider_cfg()
        if not google_provider_cfg:
            raise Exception("Could not fetch Google provider config")

        # Tạo client
        client = OAuth2Session(
            GOOGLE_CLIENT_ID,
            state=session["oauth_state"],
            redirect_uri=f"{PUBLIC_URL}/google/callback"
        )

        # Fetch token
        token = client.fetch_token(
            google_provider_cfg["token_endpoint"],
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url.replace('http://', 'https://')
        )

        # Lấy thông tin user
        resp = client.get(google_provider_cfg["userinfo_endpoint"])
        if not resp.ok:
            raise Exception("Failed to get user info")

        userinfo = resp.json()
        if not userinfo.get("email_verified"):
            flash("Email chưa được xác thực", "error")
            return redirect(url_for("login"))

        # Xử lý thông tin user
        email = userinfo["email"]
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Tạo user mới
            username = userinfo.get("name", email.split("@")[0]).lower().replace(" ", "_")
            base_username = username
            counter = 1
            
            # Đảm bảo username là duy nhất
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1

            user = User(
                username=username,
                email=email,
                social_id=userinfo["sub"],
                social_type="google"
            )
            db.session.add(user)
            db.session.commit()

        # Login user
        login_user(user)
        flash("Đăng nhập thành công!", "success")
        return redirect(url_for("dashboard"))

    except Exception as e:
        app.logger.error(f"Error in Google callback: {e}")
        flash(f"Lỗi xác thực: {str(e)}", "error")
        return redirect(url_for("login"))

# Model User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    social_id = db.Column(db.String(100), unique=True)
    social_type = db.Column(db.String(20))
    reset_token = db.Column(db.String(128))
    reset_token_expiry = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    try:
        with app.app_context():
            # Chỉ tạo database nếu chưa tồn tại
            if not os.path.exists('users.db'):
                db.create_all()
                logger.info("Database initialized successfully")
                
                # Khôi phục tài khoản từ backup nếu có
                backup_dir = os.path.join(app.root_path, 'backups')
                if os.path.exists(backup_dir):
                    for filename in os.listdir(backup_dir):
                        if filename.startswith('backup_') and filename.endswith('.txt'):
                            try:
                                with open(os.path.join(backup_dir, filename), 'r', encoding='utf-8') as f:
                                    data = {}
                                    for line in f:
                                        key, value = line.strip().split(': ', 1)
                                        data[key] = value
                                    
                                    # Kiểm tra xem tài khoản đã tồn tại chưa
                                    if not User.query.filter_by(username=data['username']).first():
                                        user = User(
                                            username=data['username'],
                                            email=data['email']
                                        )
                                        user.set_password(data['password'])
                                        db.session.add(user)
                                        
                                db.session.commit()
                                logger.info(f"Restored account from backup: {filename}")
                            except Exception as e:
                                logger.error(f"Error restoring backup {filename}: {str(e)}")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Đăng nhập thành công!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại!', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email đã được sử dụng!', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Luôn tự động sao lưu tài khoản
        backup_data = {
            'username': username,
            'email': email,
            'password': password,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Tạo thư mục backups nếu chưa tồn tại
        backup_dir = os.path.join(app.root_path, 'backups')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            
        filename = f"backup_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        backup_path = os.path.join(backup_dir, filename)
        
        # Lưu thông tin vào file
        with open(backup_path, 'w', encoding='utf-8') as f:
            for key, value in backup_data.items():
                f.write(f"{key}: {value}\n")
        
        flash('Đăng ký thành công! Thông tin tài khoản đã được tự động sao lưu.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Đã đăng xuất!', 'success')
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Tạo token reset password
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Gửi email
            reset_url = f"{PUBLIC_URL}/reset-password/{token}"
            msg = Message('Yêu cầu đặt lại mật khẩu',
                        sender='your-email@gmail.com',
                        recipients=[email])
            msg.body = f'''Để đặt lại mật khẩu, vui lòng truy cập link sau:
{reset_url}

Link này sẽ hết hạn sau 1 giờ.

Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.
'''
            mail.send(msg)
            flash('Hướng dẫn đặt lại mật khẩu đã được gửi đến email của bạn.', 'success')
            return redirect(url_for('login'))
        
        flash('Email không tồn tại trong hệ thống.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Link đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        # Cập nhật mật khẩu mới
        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Mật khẩu đã được đặt lại thành công! Vui lòng đăng nhập.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/backup', methods=['GET'])
@login_required
def backup_account():
    try:
        # Lấy thông tin người dùng hiện tại
        user_data = {
            'username': current_user.username,
            'email': current_user.email,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'social_type': current_user.social_type or 'local'
        }
        
        # Tạo tên file sao lưu
        filename = f"backup_{current_user.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Tạo file CSV trong bộ nhớ
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=user_data.keys())
        writer.writeheader()
        writer.writerow(user_data)
        
        # Chuẩn bị response
        response = app.response_class(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename={filename}.csv',
                'Content-Type': 'text/csv; charset=utf-8'
            }
        )
        
        return response
        
    except Exception as e:
        flash('Có lỗi xảy ra khi sao lưu tài khoản!', 'error')
        app.logger.error(f'Lỗi sao lưu tài khoản: {str(e)}')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    
    # Cấu hình cho production
    if os.environ.get('PRODUCTION', False):
        from waitress import serve
        serve(app, host='0.0.0.0', port=int(os.environ.get('PORT', 80)))
    else:
        # Development mode
        os.environ['FLASK_DEBUG'] = '1'
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 80)),
            debug=True
        )