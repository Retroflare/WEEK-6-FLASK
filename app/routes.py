from flask import render_template
from fragrance_app import app

@app.route('/')
def landing_page():
    return render_template('landing.jinja')

@app.route('/signin')
def signin():
    return render_template('signin.jinja')

@app.route('/register')
def register():
    return render_template('register.jinja')

@app.route('/collection')
def display_collection():
    return render_template('collection.jinja')
