document.addEventListener("DOMContentLoaded", function() {
    const passwordInput = document.getElementById("password");
    const strengthMeter = document.getElementById("strengthMeter");
    const strengthText = document.getElementById("strengthText");

    function calculateStrength(password) {
        let score = 0;
        if (!password) return score;

        //length points
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;

        //character variety
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/\d/.test(password)) score += 1;
        if (/[\W_]/.test(password)) score += 1;

        return score;
    }

    function updateStrengthMeter() {
        const password = passwordInput.ariaValueMax;
        const score = calculateStrength(password);

        const levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong", "Excellent"];
        const colors = ["#ff3e36", "#ff691f", "#ffda36", "#0be881", "#05c46b", "#009432"];

        strengthMeter.value = score;
        strengthText.textContent = levels[score];
        strengthText.style.color = colors[score];
    }

    passwordInput.addEventListener("input", updateStrengthMeter);
});