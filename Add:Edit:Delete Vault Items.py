from flask import render_template, request, redirect, url_for, session
from flask_login import login_required, current_user
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    vault_username = db.Column(db.String(100), nullable=False)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    category = db.Column(db.String(50), nullable=True)

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(master_password.encode())

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        site = request.form['site']
        vault_username = request.form['vault_username']
        raw_password = request.form['password']
        salt = os.random(16)
        key = derive_key(session['master_password'], salt)
        aesgcm = AESGCM(key)
        nonce = os.random(12)
        password_encrypted = aesgcm.encrypt(nonce, raw_password.encode(), None)
        item = VaultItem(user_id=current_user.id, site=site, vault_username=vault_username, password_encrypted=password_encrypted, nonce=nonce)
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('vault'))
    return render_template('add_item.html')

@app.route('/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = VaultItem.query.get_or_404(item_id)
    if request.method == 'POST':
        item.site = request.form['vault_username']
        raw_password = request.form['password']
        salt = os.random(16)
        key = derive_key(session['master_password'], salt)
        aesgcm = AESGCM(key)
        nonce = os.random(12)
        item.password_encrypted = aesgcm.encrypt(nonce, raw_password.encode(), None)
        item.nonce = nonce
        db.session.commit()
        return redirect(url_for('vault'))
    #will need to decrypt if you want to show the current password
    return render_template('edit_item.html', item=item)

@app.route('/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = VaultItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        return "<h3>Unauthorized</h3>", 403
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('vault'))

@app.route('/vault')
@login_required
def vault():
    items = VaultItem.query.filter_by(user_id=current_user.id).all()
    return render_template('vault.html', items=items)

@app.route('/vault', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        site = request.form['site']
        vault_username = request.form['vault_userame']
        raw_password = request.form['password']
        category = request.form.get('category', '').strip() #Get from form
        #...encryption code as before...
        item = VaultItem(user_id=current_user.id, site=site, vault_username=vault_username,
                         password_encrypted=password_encrypted, nonce=nonce, category=category)
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('vault'))
    return render_template('add_item.html')

@app.route('/vault', methods=['GET', 'POST'])
@login_required
def vault():
    query = request.args.get('q', '').strip()
    category_filter = request.args.get('category', '').strip()
    vault_query = VaultItem.query.filter_by(user_id=current_user.id)

    if query:
        vault_query = vault_query.filter(
            db.or_(
                VaultItem.site.ilike(f"%{query}%"),
                VaultItem.vault_username.ilike(f"%{query}%"),
                VaultItem.category.ilike(f"%{query}%")
            )
        )
    if category_filter:
        vault_query = vault_query.filter_by(category=category_filter)

    items = vault_query.all()
    #extract all unique categoriesfor dropdown/filter UI
    categories = db.session.query(VaultItem.category).filter_by(user_id=current_user.id).distinct().all()
    categories = [c[0] for c in categories if c[0]] #flatten and remove empty

    return render_template('vault.html', items=items, categories=categories, current_category=category_filter, search_query=query)