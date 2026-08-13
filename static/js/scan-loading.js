document.addEventListener('DOMContentLoaded', function () {
  const form = document.querySelector('form[data-loading-text]');
  if (!form) return;

  const btn = form.querySelector('button[type="submit"]');
  const loadingText = form.dataset.loadingText || 'Working…';

  form.addEventListener('submit', function () {
    btn.innerHTML = loadingText + ' <span class="spinner-border spinner-border-sm ms-2"></span>';
    btn.disabled = true;
  });
});