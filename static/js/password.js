document.addEventListener('DOMContentLoaded', function () {
  const btn = document.getElementById('pw-toggle-btn');
  if (!btn) return;

  btn.addEventListener('click', function () {
    const input = document.getElementById('password');
    const icon = document.getElementById('pw-eye');

    if (input.type === 'password') {
      input.type = 'text';
      icon.className = 'bi bi-eye-slash';
    } else {
      input.type = 'password';
      icon.className = 'bi bi-eye';
    }
  });
});