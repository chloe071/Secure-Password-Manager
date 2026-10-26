from app import User
from flask import session

@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'username' not in session:
        return redirect(url_for('login')) # type: ignore
    
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.mfa_secret:
        return redirect(url_for) # type: ignore
    
    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(token):
            login_user(user) #complete login after MFA success
            session.pop('username', None)
            return redirect(url_for('vault'))
        else:
            return '<h3>Invalid MFA token. Try again.</h3'
        
    return '''
        <form method="POST>
           Enter MFA Token: <input type="text" autofocus>
           <input type="submit" value="Verify">
        </form>
    '''

app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('vault'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if user.mfa_secret:
                #save username in session and redirect to MFA verify page
                session['username'] = username
                return redirect(url_for('verify_mfa'))
            else:
                login_user(user) #no MFA setup login directly
                return redirect(url_for('vault'))
        else:
            return '<h3>Invalid username or password</h3>'
        return render_template('login.html')