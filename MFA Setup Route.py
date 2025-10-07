class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(b.String(128), nullable=False)
    mfa_secret = db.Column(db.String(32), default=None) # totp secret key

import pyotp
import qrcode
import io
import base64

@app.route('/setup_mfa')
@login_required
def setup_mfa():
    if current_user.mfa_secret is None:
        secret = pyotp.random_base32()
        current_user.mfa_secret = secret
        db.session.commit()
    else:
        secret = current_user.mfa_secret
    #build provisioning URI for google authenticator or similar apps
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(current_user.username, issuer_name="SecurePM")

    #generate QR code image from OTP URI
    qr = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return f'''
        <h1>Scan this QR code with your authenticator app</h1>
        <img src="data:image/png;base64,{img_str}">
        <p>Or enter this secret manually: <b>{secret}</b></p>
        <a href="/verify_mfa"Proceed to Verify MFA</a>
        '''