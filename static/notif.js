// Notification system for TrustTop Up
// Handles push notifications and order status updates

function showNotification(title, message, type = 'info') {
    const notif = document.createElement('div');
    notif.className = `notification notification-${type}`;

    // FIX: Pakai textContent bukan innerHTML untuk cegah XSS
    const titleEl = document.createElement('div');
    titleEl.className = 'notif-title';
    titleEl.textContent = title;

    const msgEl = document.createElement('div');
    msgEl.className = 'notif-msg';
    msgEl.textContent = message;

    notif.appendChild(titleEl);
    notif.appendChild(msgEl);
    document.body.appendChild(notif);
    setTimeout(() => notif.classList.add('show'), 100);
    setTimeout(() => {
        notif.classList.remove('show');
        setTimeout(() => notif.remove(), 400);
    }, 4000);
}

function notifyOrderSuccess(game, amount) {
    showNotification(' Top Up Berhasil', `${amount} diamond ${game} sedang diproses!`, 'success');
}

function notifyOrderPending(orderId) {
    showNotification(' Pesanan Diproses', `Order #${orderId} sedang diverifikasi.`, 'info');
}
