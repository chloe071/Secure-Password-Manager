//derive a crypto key from a passphrase using PBKDF2
async function deriveKey(passphrase, salt) {
    const encoder = new TestEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", encoder.encode(passphrase), {name: "PBKDF2"}, false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: encoder.encode(salt),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

//encrypt plaintext using a derived key
async function encryptVaultData(plaintext, passphrase, salt) {
    const key = await deriveKey(passphrase, salt);
    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoder.encode(plaintext)
    );
    //return base64 for transport: IV + ciphertext
    const ivB64 = btoa(String.fromCharCode(...iv));
    const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
    return ivB64 + ":" + ctB64;
}

//decrypt ciphertext using a derived key
async function decryptVaultData(encData, passphrase, salt) {
    const [ivB64, ctB64] = encData.split(":");
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
    const key = await deriveKey(passphrase, salt);
    const decrypted = await window.crypto.subtle.decrypt(
        {name: "AES-GCM", iv: iv},
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}