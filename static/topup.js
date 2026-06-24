// ===== TOP UP PAGE (UniPin-style) =====

function updateSummary() {
  const userId = document.getElementById('user-id')?.value.trim() || '-';
  const serverInput = document.getElementById('server-id');
  const serverSelect = document.getElementById('server-select');
  const serverVal = serverInput ? serverInput.value.trim() : (serverSelect ? serverSelect.value : '');

  const idDisplay = serverVal ? `${userId} / ${serverVal}` : userId;
  document.getElementById('summary-id').textContent = idDisplay || '-';

  const selectedAmount = document.querySelector('.amount-option.selected');
  document.getElementById('summary-item').textContent = selectedAmount ? selectedAmount.dataset.label : '-';

  const selectedPayment = document.querySelector('.payment-option.selected');
  document.getElementById('summary-payment').textContent = selectedPayment ? selectedPayment.dataset.method : '-';

  const total = selectedAmount ? selectedAmount.dataset.price : 'Rp 0';
  document.getElementById('summary-total').textContent = total;
}

function selectAmount(btn) {
  document.querySelectorAll('.amount-option').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  updateSummary();
}

function selectPayment(btn) {
  document.querySelectorAll('.payment-option').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  updateSummary();
}

// Live-update summary bar as the customer types their ID
['user-id', 'server-id'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('input', updateSummary);
});
const serverSelectEl = document.getElementById('server-select');
if (serverSelectEl) serverSelectEl.addEventListener('change', updateSummary);

// Pre-select the first amount option by default, like the old modal did
document.addEventListener('DOMContentLoaded', () => {
  const firstAmount = document.querySelector('.amount-option');
  if (firstAmount) firstAmount.classList.add('selected');
  updateSummary();
});

function highlightError(el) {
  if (!el) return;
  el.classList.add('input-error');
  el.addEventListener('input', () => el.classList.remove('input-error'), { once: true });
}

function submitTopupForm() {
  const gameName = document.getElementById('game-name').value;
  const userIdEl = document.getElementById('user-id');
  const userId = userIdEl?.value.trim() || '';

  if (!userId) {
    highlightError(userIdEl);
    userIdEl?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return;
  }

  let serverId = '';
  const serverInput = document.getElementById('server-id');
  const serverSelect = document.getElementById('server-select');
  if (serverInput) {
    serverId = serverInput.value.trim();
    if (!serverId) {
      highlightError(serverInput);
      serverInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
  } else if (serverSelect) {
    serverId = serverSelect.value;
  }

  const selectedAmount = document.querySelector('.amount-option.selected');
  if (!selectedAmount) {
    document.getElementById('amount-grid')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return;
  }

  const selectedPayment = document.querySelector('.payment-option.selected');
  const paymentMethod = selectedPayment ? selectedPayment.dataset.method : 'Dana';

  const emailEl = document.getElementById('email');
  const email = emailEl?.value.trim() || '';
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    highlightError(emailEl);
    emailEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return;
  }

  const voucherCode = document.getElementById('voucher-code')?.value.trim().toUpperCase() || '';
  const csrfToken = document.getElementById('csrf-token-value')?.value || '';

  const btn = document.getElementById('summary-bar-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Processing...'; }

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/checkout';

  const fields = {
    game: gameName,
    user_id: userId,
    server_id: serverId,
    diamond: selectedAmount.dataset.label,
    price: selectedAmount.dataset.price,
    payment: paymentMethod,
    voucher_code: voucherCode,
    email: email,
    csrf_token: csrfToken,
  };

  for (const [key, val] of Object.entries(fields)) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = key;
    input.value = val;
    form.appendChild(input);
  }

  document.body.appendChild(form);
  form.submit();
}
