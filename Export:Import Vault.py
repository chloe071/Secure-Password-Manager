import csv
from flask import Response
from io import StringIO

@app.route('/export')
@login_required
def export_vault():
    vault_items = VaultItem.query.filter_by(user_id=current_user.id).all()

    #Create a StringIO in CSV format
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['site', 'vault_username', 'password_encrypted_base64', 'category']) #headers

    for item in vault_items:
        encrypted_base64 = base64.b64encode(item.password_encrypted).decode()
        cw.writerow([item.site, item.vault_username, encrypted_base64, item.category or ""])

    output = si.getvalue()
    si.close()

    return Response(output,
                    mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=vault_export.csv"})

import base64
from flask import request, flash

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_vault():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('No file selected', 'danger')
            return redirect(url_for('import_vault'))
        
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_imput = csv.reader(stream)
        headers = next(csv_input, None)
        expected_headers = ['site', 'vault_username', 'password_encrypted_base64', 'category']

        if headers != expected_headers:
            flash('Invalid CSV format', 'danger')
            return redirect(url_for('import_vault'))
        
        for row in csv_input:
            site, vault_username, encrypted_b64, category = row
            password_encrypted = base64.b64decode(encrypted_b64)

            #Create vaultItem and add it 
            item = VaultItem(user_id=current_user.id, site=site, vault_username=vault_username,
                             password_encrypted=password_encrypted, nonce=os.urandom(12), category=category)
            db.session.add(item)

        db.session.commit()
        flash('Vault imported successfully', 'success')
        return redirect(url_for('vault'))
    return '''
     <h2>Import Vault (CSV)</h2>
     <form method="POST" enctype="multipart/form-data">
         <input type="file" name="file" accept=".csv" required>
         <button type="submit">Import</button>
     </form>
     '''

