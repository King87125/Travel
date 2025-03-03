from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from openai import OpenAI
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "your-secret-key")  # 设置一个随机的密钥
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # 使用 SQLite 存储用户数据
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  # 重定向未登录用户到登录页面

# OpenAI 客户端设置
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
)

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# 数据库初始化（手动执行）
with app.app_context():
    db.create_all()

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('登录失败，请检查用户名和密码', 'danger')
    
    return render_template('login.html')

# 注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('密码和确认密码不一致，请重新输入')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('注册成功，现在可以登录！', 'success')
            return redirect(url_for('login'))
        except:
            flash('用户名已存在，请选择其他用户名', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

# 登出路由
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# 登录后首页
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# 旅行助手接口
@app.route('/ask', methods=['POST'])
def ask():
    try:
        data = request.json
        question = data.get('question', '')
        
        completion = client.chat.completions.create(
            model="deepseek-r1",
            messages=[{'role': 'user', 'content': question}]
        )
        
        return jsonify({
            'reasoning': completion.choices[0].message.reasoning_content,
            'answer': completion.choices[0].message.content
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 用户加载
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 每次请求前检查是否已登录
@app.before_request
def ensure_logged_in():
    """在每次请求前检查用户是否已登录"""
    if not current_user.is_authenticated and request.endpoint not in ['login', 'register']:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=5000, debug=True)