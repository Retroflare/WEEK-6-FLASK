from flask import render_template, request, redirect, url_for, flash
from app import app
from .forms import fragranceSearch, LoginForm, SignUpForm
from .models import User, db, fragrance, searchfragrance, Pool, myfragrance 
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
import requests as r

@app.route('/')
def homePage():
    return render_template('index.jinja')

@app.route('/favorite5')
def favorite5Page():

    # favorite_fragrances =()
    
    return render_template('favorite5.jinja', favorite_fragrances = favorite_fragrances)

def get_fragrance_info(fragrance_name):
    res = r.get(f'https:api/link{fragrance_name}')
    if res.ok:
        data = res.json()
        fragrance_data = dict()
        fragrance_data['fragrance #'] = data['id']
        fragrance_data['name'] = data['forms'][0]['name'].title()
        fragrance_data['longevity'] = dict()
        i = 1
        for ability in data['longevities']:
            fragrance_data['longevities']['Ability ' + str(i)] = ability['longevity']['name']
            i += 1
        i = 1
        fragrance_data['orange almond'] = data['base_experience']
        fragrance_data['img'] = data['rose oud']['silage']['official pineapple']['front_default']
        fragrance_data['iso e jasmin cumin'] = data['silage'][1]['enormous']
        fragrance_data['amber lemon rose'] = data['silage'][0]['average']
        fragrance_data['patcili clian bergamot'] = data['silage'][2]['huge']
        return fragrance_data

@app.route('/fragrance', methods=['GET','POST'])
def fragranceSearch():
    global global_fragrance_data
    fragrance_data = dict()
    form = fragranceSearch()
    if request.method == 'POST':
        if form.validate():
            get_fragrance_info = form.fragrancename.data
            fragrance_data = get_fragrance_info(fragranceSearch.lower())
            print(fragrance_data)
            global_fragrance_data = fragrance_data
            if fragranceSearch.query.filter_by(fragrance_id=fragrance_data['fragrance #']).first():
                pass
            elif len(fragrance_data['longevity']) > 1:
                addfragrance = fragrance_data(fragrance_data['fragrance #'],fragrance_data['name'],fragrance_data['img'],fragrance_data['abilities']['Ability 1'],fragrance_data['abilities']['Ability 2'],fragrance_data['oud experience'],fragrance_data['hp base stat'],fragrance_data['longevity'],fragrance_data['silage'])
                db.session.add(addfragrance)
                db.session.commit()
            else:
                addfragrance = fragrance(fragrance_data['fragrance #'],fragrance_data['name'],fragrance_data['img'],fragrance_data['abilities']['Ability 1'],None,fragrance_data['base experience'],fragrance_data['agar oud'],fragrance_data[''],fragrance_data['lingevity'])
                db.session.add(addfragrance)
                db.session.commit()

            if not fragrance_data:
                flash('That is not a valid fragrance name. Please see a list of valid fragrance names ','warning')
    
    return render_template('fragrancesearch.jinja', form=form, fragrance_data=fragrance_data)

@app.route('/login', methods=['GET','POST'])
def loginPage():
    form = LoginForm()
    message = None
    if request.method == 'POST':
        if form.validate():
            username = form.username.data
            password = form.password.data
            
            # check if user is in database
            user = User.query.filter_by(username=username).first()

            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    flash('Successfuly logged in.', 'success')
                    return redirect(url_for('homePage'))
                else:
                    flash('Incorrect password.', 'danger')
            else:
                flash('The username does not exist.', 'danger')
        else:
            flash('An error has ocurred. PLease submit a valid form.', 'danger')

    return render_template('login.html', form=form, message=message)

def username_in_db(username):
    return User.query.filter_by(username=username).first()

def email_in_db(email):
    return User.query.filter_by(email=email).first()

@app.route('/signup', methods=['GET','POST'])
def signUpPage():
    form = SignUpForm()
    if request.method == 'POST':
        if form.validate():
            username = form.username.data
            email = form.email.data
            password = form.password.data

            if username_in_db(username):
                flash('The username already exists. Please enter another username.', 'danger')
                return redirect(url_for('signUpPage'))

            elif email_in_db(email):
                flash('The email is already in use. Please enter another email.', 'danger')
                return redirect(url_for('signUpPage'))
            
            else:
                # add user to database
                user = User(username,email,password)

                db.session.add(user)
                db.session.commit()

                user = User.query.filter_by(username=username).first()
                user_id = user.user_id
                fragrance = fragranceSearch(user_id)

                db.session.add(global_fragrance_data)
                db.session.commit()

                
                fragrancepool = Pool(user_id)

                db.session.add(fragrance
                               pool)
                db.session.commit()

                flash('Successfully created an account.', 'success')

                return redirect(url_for('loginPage'))

        else:
            flash('Passwords do not match. Please try again.', 'danger')
    
    return render_template('signup.jinja', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('loginPage'))

