from werkzeug.security import generate_password_hash, check_password_hash
#from mongoengine import Document, StringField

from pymongo import MongoClient
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

from flask import jsonify, render_template, request, url_for
#, send_file
from flask import Flask, flash, redirect, send_file
import pdb
import mimetypes
import os
import io

import gridfs
import chardet
import magic
from functools import wraps
from flask import abort
app = Flask(__name__)

app.config['SESSION_COOKIE_SECURE'] = False

app.secret_key = 'supersecretkeyankur'  # Change to a secure, hard-to-guess value
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if not logged in
from bson import ObjectId

@login_manager.user_loader
def load_user(user_id):
    print(f"[DEBUG] load_user called with user_id: {user_id}")
    try: 
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            print(f"[DEBUG] User found: {user_data['username']}")
            return User(user_data)
    except Exception as e:
        print(f"[DEBUG] Error loading user: {e}")
    return None




FILE_SYSTEM_ROOT =os.getcwd()


client = MongoClient("mongodb+srv://mongodb:mongodb@cluster0.ps5mh8y.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
# Get and Post Route
bflag=True
db = client.dataankur
gender=""
age=""
users_collection = db['users']

ages="Zakat Projects,Self Relience,Scholarship,Treatment,Flood,Blanket,Food"
agetra=ages.split(',')

admin_user = {
    "username": "admin",
    "password": generate_password_hash("admin123"),
    "email": "zamia.chowdhury@gmail.com",
    "role": "admin"
}

if not users_collection.find_one({'username': "admin"}):
    users_collection.insert_one(admin_user)
#pdb.set_trace()
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or getattr(current_user, 'role', 'user') != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function
from flask_login import UserMixin



class User(UserMixin):
    def __init__(self, user_dict):
        self.id = str(user_dict['_id'])  # Flask-Login uses this in get_id()
        self.username = user_dict['username']
        self.role = user_dict.get('role', 'user')
    


    def get_id(self):
        return self.id

    # Optionally: def get_id(self): return str(self.id)


def connectToDb(namesp):
    fs = gridfs.GridFS(db,namesp)
    return db,fs


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = list(users_collection.find({}, {'_id': 0, 'username': 1, 'email': 1, 'role': 1}))
    #users = list(users_collection.find({}, {'_id': 0, 'username': 1}))    
    return render_template('admin_dashboard.html', users=users)

@app.route('/promote_user', methods=['POST'])
@login_required
@admin_required
def promote_user():
    username = request.form['username']
    users_collection.update_one({'username': username}, {'$set': {'role': 'admin'}})
    flash(f'{username} promoted to admin.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/demote_user', methods=['POST'])
@login_required
@admin_required
def demote_user():
    username = request.form['username']
    users_collection.update_one({'username': username}, {'$set': {'role': 'user'}})
    flash(f'{username} demoted to user.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user', methods=['POST'])
@login_required
@admin_required
def delete_user():
    username = request.form['username']
    users_collection.delete_one({'username': username})
    flash(f'{username} deleted.', 'danger')
    return redirect(url_for('admin_dashboard'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    # pdb.set_trace()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if users_collection.find_one({'username': username,'role':'user'}):
            flash('Username already exists. Choose a different one.', 'danger')
            return render_template('register.html')
        # else:
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'email': email,
            'role': 'user'  # or 'admin' for admin users
        })

        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')
    
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # pdb.set_trace()
    if request.method == 'POST':
        email = request.form['email']
        user = users_collection.find_one({'email': email,'role':'user'})
        
        if user:
            return render_template('reset_password.html', username=user['username'])
        else:
            flash('Email not found', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')
@app.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form['username']
    new_password = request.form['password']
    
    hashed_password = generate_password_hash(new_password)
    
    result = users_collection.update_one(
        {'username': username},
        {'$set': {'password': hashed_password}}
    )
    
    if result.modified_count > 0:
        flash('Password updated successfully.', 'success')
    else:
        flash('Error updating password.', 'danger')

    return redirect(url_for('login'))

@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
 
    if request.method == 'POST':
        email = request.form['email']
        user = users_collection.find_one({'email': email,'role':'user'})
        if user:
            flash(f"Your username is: {user['username']}", 'info')
        else:
            flash("Email not found", 'danger')
            return redirect(url_for('forgot_username')) # OR render_template('login.html')

    return render_template('forgot_username.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']        
        user = users_collection.find_one({'username': username})    
        if user and check_password_hash(user['password'], password):
            user_obj = User(user)
            login_user(user_obj)
            print(user_obj)
            flash('Login successful.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/get_file/<namef>/<category>', methods=['GET','POST'])
@login_required
def get_file(namef=None,category=None):
    global agetra
    #pdb.set_trace()
    if request.method=="POST":
        category=request.form['category']
        db,fs = connectToDb(category)
        return render_template('get_file.html',url=request.url, names=fs.list(),category=category)
    else:
        if namef is not None:
            db, fs = connectToDb(category)    
            file = fs.find_one({'filename': namef})
            if file:
                grid_out = fs.find_one({'filename': namef})
                if grid_out:
                    file_data = io.BytesIO(grid_out.read())               
                    mimetype, _ = mimetypes.guess_type(namef)
                    print(mimetype)
                    if not mimetype:
                        if namef.endswith(('.jpg', '.jpeg')):
                            mimetype = 'image/jpeg'
                        elif namef.endswith('.png'):
                            mimetype = 'image/png'
                        elif namef.endswith('.gif'):
                            mimetype = 'image/gif'
                        elif namef.endswith('.pdf'):
                            mimetype = 'application/pdf'
                        else:
                            mimetype = 'application/octet-stream'
                    return send_file(file_data, mimetype=mimetype, download_name=namef)
            else:
                return "File not found", 404
    return render_template('filter.html')
@app.route('/delete_file', methods=['POST','GET'])
@login_required
@admin_required
def delete_file():
    global agetra
    global db
   # pdb.set_trace()
    if request.method=="POST":
        files=request.form.getlist('files[]')
        for file in files:
            rs=file.split(',')
            category=rs[0]
            db, fs = connectToDb(category)
            for x in fs.find({'filename':rs[1] }).distinct('_id'):
                fs.delete(x)
                print('file' +rs[1] +'is deleted')
        return jsonify({'message': 'file is deleted'}), 201
    else:
        rs=[]
        files_a={}
        for i in agetra:
            fs = gridfs.GridFS(db,i)
            if len(fs.list())>0:
                files_a[i]=fs.list()
        return render_template('delete_file.html', names=files_a)
    return render_template('filter.html')
@app.route('/list_file',methods=['GET'])
@login_required
def list_file():
    global db
    global agetra
    rs=[]
    files_a={}
    for i in agetra:
        fs = gridfs.GridFS(db,i)
        if len(fs.list())>0:
            files_a[i]=fs.list()
    return render_template('get_file_all.html', names=files_a)

@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    #pdb.set_trace()
    if request.method == "POST":
        category=request.form['category']
        files = request.files.getlist("file[]")
        for file in files:
            if file.filename == '':
                msg = "No selected file"
                return render_template('upload.html', msgs=msg)
            file_bytes = file.read(2048)  # Read a chunk of the file
            mime_type = magic.from_buffer(file_bytes, mime=True)
            file.seek(0)  # Reset file pointer so fs.put() reads the full fil
            if mime_type == 'application/pdf':
                db,  fs = connectToDb(category)
                file_id = fs.put(file, filename=file.filename)
            elif mime_type and mime_type.startswith('image/'):
                db, fs = connectToDb(category)
                file_id = fs.put(file, filename=(file.filename ), content_type=mime_type)              
            else:
                db, fs = connectToDb(category)
                file_id = fs.put(file, filename=(file.filename ), content_type=mime_type)     
                #return render_template('upload.html', msgs='Only PDF or image files are allowed')
        return render_template('upload.html',msgs='file is uploaded')
    else:
        return render_template('index.html')
   
if __name__ == '__main__':
    app.run(host='0.0.0.0')
