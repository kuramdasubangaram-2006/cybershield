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
    message.textContent = "Password reset is not available yet. Ask your administrator for help.";
    message.classList.remove("d-none");
  });
});
