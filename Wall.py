from flask import  Flask, render_template, redirect, request, session, flash
# import the Connector function
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = 'sdfds34314efdst1'
bcrypt = Bcrypt(app)
import re
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# connect and store the connection in "mysql" note that you pass the database name to the function
mysql = MySQLConnector(app, 'wall')
# import Flask
from flask import Flask, render_template, redirect, request, session, flash
# the "re" module will let us perform some regular expression operations
import re
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
lowercase = re.compile("[a-z]+")
uppercase = re.compile("[A-Z]+")
number = re.compile('[0-9]+')
app = Flask(__name__)
app.secret_key = "!ds^anxfdws*&ds^sjkss"
@app.route('/', methods=['GET'])
def index():
    if "first_name" in session:
        return redirect('/dashboard')
    return render_template("index.html")
@app.route('/register', methods=['POST'])
def register():
    flash(request.form['email'],'email')
    flash(request.form['first_name'],"first_name")
    flash(request.form['last_name'],'last_name')
    sucess = 0
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!","email_err")
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!","email_err")
    else:
        sucess += 1
    if len(request.form['first_name']) < 1:
        flash("Please enter a first name.","first_name_err")
    elif  len(request.form['first_name']) < 3 or number.search(request.form['first_name']):
        flash("Please enter a valid first name.","first_name_err")
    else:
        sucess += 1
    if len(request.form['last_name']) < 1:
        flash("Please enter a last name.","last_name_err")
    elif len(request.form['first_name']) < 3 or number.search(request.form['last_name']):
        flash("Please enter a valid last name.","last_name_err")
    else:
        sucess += 1
    if len(request.form['password']) < 1:
        flash("Please enter a password.","password_err")
    elif len(request.form['password']) < 8:
        flash("Please enter a password at least 8 characters long.","password_err")
    elif not (lowercase.search(request.form['password'])):
        flash("Please enter a password containing a lowercase.","password_err")
    elif not (uppercase.search(request.form['password'])):
        flash("Please enter a password containing an uppercase.","password_err")
    elif not number.search(request.form['password']):
        flash("Please enter a password containing a number.","password_err")
    else:
        sucess += 1
        pw_hash = bcrypt.generate_password_hash(request.form['password'])

    if len(request.form['confirm']) < 1:
        flash("Please enter a password confirmation.","confirm_err")
    elif request.form['password'] == request.form['confirm']:
        sucess += 1
    else:
        flash("Passwords do not match","confirm_err")

    if sucess >=5:
        flash("User registered!","sucess")
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"
        data = {'first_name': request.form['first_name'], 'last_name': request.form['last_name'], 'email': request.form['email'], 'password':pw_hash}
        mysql.query_db(query, data)
        query = "SELECT * FROM users WHERE email = :email"
        data = {'email': request.form['email']}
        user = mysql.query_db(query, data)
        session['id'] = user[0]['id']
        session['first_name'] = user[0]['first_name']
        session['last_name'] = user[0]['last_name']
        flash(request.form['first_name'] + " " + request.form['last_name'] + " has been registered!","sucess")
        flash('','email')
        flash('',"first_name")
        flash('','last_name')
        return redirect('/dashboard')
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    success = 0
    query = "SELECT * FROM users WHERE email = :email"
    data = {'email': request.form['email']}
    user = mysql.query_db(query, data)
    pw_hash = ''
    if len(user) == 0:
        flash("There is no such email.","email_login_err")
        return redirect('/')
    else:
        pw_hash = user[0]['password']
        success += 1
    if not bcrypt.check_password_hash(pw_hash, request.form['password']):
        flash("Password does not match.","password_login_err")
    else:
        success += 1
    if success >= 2:
        session['id'] = user[0]['id']
        session['first_name'] = user[0]['first_name']
        session['last_name'] = user[0]['last_name']
        return redirect('/dashboard')
    return redirect('/')

@app.route('/logout')
def logout():
    flash( session['first_name'] + " " + session['last_name'] + " has logout!","message")
    session.clear()
    return redirect('/')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    query = "SELECT messages.id, messages.message, DATE_FORMAT(messages.created_at,'%b %d %Y') as created_at, DATE_FORMAT(messages.updated_at,'%b %d %Y') as updated_at, messages.user_id, users.first_name, users.last_name FROM messages JOIN users ON users.id = messages.user_id ORDER BY messages.created_at DESC;"
    messages = mysql.query_db(query)
    query = "SELECT comments.id, comments.comment, DATE_FORMAT(comments.created_at,'%b %d %Y') as created_at, DATE_FORMAT(comments.updated_at,'%b %d %Y') as updated_at, comments.message_id, comments.user_id, users.first_name, users.last_name from comments JOIN users ON users.id = comments.user_id ORDER BY comments.created_at ASC"
    comments = mysql.query_db(query)
    return render_template('wall.html', messages = messages, comments = comments)

@app.route("/post/message", methods=['POST'])
def message():
    query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (:message, NOW(), NOW(), :id)"
    data = {'message': request.form['message'], 'id': session['id']}
    mysql.query_db(query, data)
    return redirect('/dashboard')

@app.route("/post/comment/<message_id>", methods=['POST'])
def comment(message_id):
    query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) VALUES (:comment, NOW(), NOW(), :user_id, :message_id)"
    data = {'comment': request.form['comment'], 'user_id': session['id'], 'message_id': message_id}
    mysql.query_db(query, data)
    return redirect('/dashboard')

@app.route("/delete_comment/<comment_id>", methods=['POST'])
def del_comment(comment_id):
    query = "DELETE FROM comments WHERE id = :id"
    data = {'id': comment_id}
    mysql.query_db(query, data)
    flash("Comment has been removed!")
    return redirect('/dashboard')

@app.route("/delete_message/<message_id>", methods=['POST'])
def del_message(message_id):
    query = "DELETE FROM comments WHERE message_id = :id"
    data = {'id': message_id}
    mysql.query_db(query, data)
    query = "DELETE FROM messages WHERE id = :id"
    mysql.query_db(query, data)
    flash("Comment has been removed!")
    return redirect('/dashboard')

app.run(debug=True)
