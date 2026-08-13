document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.hash-copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const targetId = btn.dataset.target;
      const text = document.getElementById(targetId).textContent.trim();

      navigator.clipboard.writeText(text).then(function () {
        const icon = btn.querySelector('i');
        icon.className = 'bi bi-clipboard-check';
        btn.style.color = 'var(--amber)';

        setTimeout(function () {
          icon.className = 'bi bi-clipboard';
          btn.style.color = '';
        }, 1500);
      });
    });
  });
});