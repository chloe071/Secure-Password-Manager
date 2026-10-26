// Strength meter, reveal/copy with clipboard clearing, and generator.
// Loaded as a static file so the Content-Security-Policy can forbid inline scripts.
(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  async function post(url, body) {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'X-CSRFToken': csrf },
      body: body || new URLSearchParams(),
      credentials: 'same-origin',
    });
    return resp.json();
  }

  // Password strength meter (from prototypes/PasswordStrengthMeter.js)
  const pwInput = document.getElementById('password');
  const meter = document.getElementById('strengthMeter');
  const meterText = document.getElementById('strengthText');
  function strength(p) {
    let s = 0;
    if (!p) return 0;
    if (p.length >= 8) s++;
    if (p.length >= 12) s++;
    if (/[a-z]/.test(p)) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[\W_]/.test(p)) s++;
    return s;
  }
  const levels = ['Very weak', 'Very weak', 'Weak', 'Moderate', 'Strong', 'Very strong', 'Excellent'];
  if (pwInput && meter) {
    pwInput.addEventListener('input', function () {
      const s = strength(pwInput.value);
      meter.value = s;
      meterText.textContent = pwInput.value ? levels[s] : '';
    });
  }

  // Reveal
  document.querySelectorAll('.reveal-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const span = document.getElementById('pw-' + btn.dataset.id);
      if (btn.textContent === 'Hide') {
        span.textContent = '••••••••';
        btn.textContent = 'Show';
        return;
      }
      const data = await post(btn.dataset.url);
      span.textContent = data.password || data.error;
      btn.textContent = 'Hide';
    });
  });

  // Copy, then clear the clipboard after 30 seconds (from prototypes/ClipboardMonitor.js)
  document.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const data = await post(btn.dataset.url);
      if (!data.password || !navigator.clipboard) return;
      await navigator.clipboard.writeText(data.password);
      btn.textContent = 'Copied';
      setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      setTimeout(function () { navigator.clipboard.writeText('').catch(function () {}); }, 30000);
    });
  });

  // Confirm deletes
  document.querySelectorAll('.delete-form').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!confirm('Delete this item?')) e.preventDefault();
    });
  });

  // Generator page
  const genForm = document.getElementById('pwdForm');
  if (genForm) {
    genForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const data = await post(genForm.dataset.url, new URLSearchParams(new FormData(genForm)));
      document.getElementById('generatedPassword').textContent = data.password || data.error;
    });
  }

  // "Generate strong password" button on add/edit form
  const fill = document.getElementById('fillGenerated');
  if (fill && pwInput) {
    fill.addEventListener('click', async function () {
      const body = new URLSearchParams({ length: '20', use_symbols: 'on' });
      const data = await post('/generate', body);
      if (data.password) {
        pwInput.type = 'text';
        pwInput.value = data.password;
        pwInput.dispatchEvent(new Event('input'));
      }
    });
  }
})();
