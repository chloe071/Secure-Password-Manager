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
                    mimetype="text/csv")