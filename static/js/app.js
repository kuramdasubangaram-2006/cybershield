document.addEventListener("DOMContentLoaded", () => {
  const passwordInput = document.querySelector("#password");
  const passwordToggle = document.querySelector("#toggle-password");

  if (passwordInput && passwordToggle) {
    passwordToggle.addEventListener("click", () => {
      const isHidden = passwordInput.type === "password";
      passwordInput.type = isHidden ? "text" : "password";
      passwordToggle.textContent = isHidden ? "Hide" : "Show";
      passwordToggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
      passwordToggle.setAttribute("aria-pressed", String(isHidden));
    });
  }

});
