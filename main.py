import functools
import os
from flask import Flask, g, session, render_template, request, url_for, redirect, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from database import connect_to_db, query_db

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(12).hex()

DATABASE_NAME = 'database.db'

# decorators
def db_write(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        func(*args, **kwargs)
        g.conn.commit()
    return wrapper

def must_be_logged_in(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Must be logged in!")
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return wrapper

# database utilities
@db_write
def insert_user(username, password):
    g.conn.execute("insert into user (username, password_hash) values (?, ?)",
                   [username, password])

def get_userdata(username):
    data = query_db(g.conn, 'select * from user where username = ?', [username])
    return data if data is None else data[0]

@db_write
def insert_password_info(site, password):
    g.conn.execute("insert into passwords (site, password, user_id) values (?, ?, ?)",
                   [site, password, session['user_id']])

def get_password_info():
    data = query_db(g.conn, 'select * from passwords where user_id = ?',
                    [session['user_id']])
    if data is None:
        return []
    return data

@db_write
def delete_password_entry(password_id):
    g.conn.execute("delete from passwords where password_id = ?", [password_id])

# general connections
@app.before_request
def before_request():
    g.conn = connect_to_db(DATABASE_NAME)
    if 'user_id' in session:
        g.user = query_db(g.conn, 'select * from user where user_id = ?', [session['user_id']])[0]
    else:
        g.user = None

@app.teardown_request
def teardown_request(_):
    if g.conn is not None:
        g.conn.close()

@app.route('/')
def home():
    return render_template('index.html')

# Logging in and signing out connections
@app.route('/login_page')
def login_page():
    return render_template('login.html')

@app.route('/signup_page')
def signup_page():
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data.get("username")
        password = data.get("password")
        userdata = get_userdata(username)
        if userdata is not None:
            if check_password_hash(userdata['password_hash'], password):
                user_id = query_db(g.conn, 'select user_id from user where username = ?',
                                   [username])[0]['user_id']
                g.conn.commit()
                session['user_id'] = user_id
            else:
                flash("Incorrect password")
                return redirect(url_for('login_page'))
        else:
            flash("Username doesn't exist")
            return redirect(url_for('login_page'))
        return redirect(url_for('home'))
    flash("Invalid URL!")
    return redirect(url_for('home'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        username = data.get("username")
        password = generate_password_hash(data.get("password"), "sha256")
        insert_user(username, password)
        return redirect(url_for('home'))
    flash("Invalid URL!")
    return redirect(url_for('home'))

@app.route('/logout')
@must_be_logged_in
def logout():
    session.pop('user_id', None)
    g.user = None
    return redirect(url_for('home'))

# Password manager connections
@app.route('/passwords_page')
@must_be_logged_in
def passwords():
    return render_template("passwords.html", passwords=get_password_info())

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        data = request.form
        site = data.get("site")
        password = data.get("password")
        insert_password_info(site, password)
        return redirect(url_for('passwords'))
    flash("Invalid URL!")
    return redirect(url_for('home'))

@app.route('/delete_password', methods=['GET', 'POST'])
def delete_password():
    if request.method == 'POST':
        password_id = int(request.json["passwordId"])
        delete_password_entry(password_id)
        return jsonify({})
    flash("Invalid URL!")
    return redirect(url_for('home'))

# main
if __name__ == "__main__":
    print("Running Flask app")
    # TODO: Add WSGI container for production environment (e.g. Gevent, Gunicorn, etc.)
    app.run(port=3000, debug=True)
