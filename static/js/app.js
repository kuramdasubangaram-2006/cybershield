document.addEventListener("DOMContentLoaded", () => {
  const passwordInput = document.querySelector("#password");
  const passwordToggle = document.querySelector("#toggle-password");
  const forgotPassword = document.querySelector("#forgot-password");
  const message = document.querySelector("#form-message");

  if (passwordInput && passwordToggle) {
    passwordToggle.addEventListener("click", () => {
      const isHidden = passwordInput.type === "password";
      passwordInput.type = isHidden ? "text" : "password";
      passwordToggle.textContent = isHidden ? "Hide" : "Show";
      passwordToggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
      passwordToggle.setAttribute("aria-pressed", String(isHidden));
    });
  }

  forgotPassword?.addEventListener("click", () => {
    if (!message) return;
    message.textContent = "Password recovery is not available on this page. User accounts can ask an administrator to set a temporary password.";
    message.classList.remove("d-none");
  });
});
