document.addEventListener("DOMContentLoaded", function () {
    function clearClipboardAfterTimeout(timeout = 30000) {  //default 30 sec
        if (!navigator.clipboard) return;

        setTimeout(() => {
            navigator.clipboard.writeText('')
            .then(() => console.log('Clipboard cleared for security.'))
            .catch(err => console.error('Failed to clear clipboard:', err))
        }, timeout);
    }

    //attach event listener to password copy buttons
    document.querySelectorAll('.copy-password-btn').forEach(button => {
        button.addEventListener('click', function () {
            const password = this.dataset.password; //assuming password stored here
            if (navigator.clipboard) {
                navigator.clipboard.writeText(password)
                .then(() => {
                    alert('Password copied to clipboard. It will be cleared after 30 seconds.')
                    clearClipboardAfterTimeout();
                })
                .catch(() => alert('Failed to copy password.'));
            }
        });
    });
});