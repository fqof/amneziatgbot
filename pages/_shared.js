let _toastTimer;
const showToast = (msg) => {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
};

const copyText = (text, msg) => {
  if (!text) return;
  navigator.clipboard?.writeText(text)
    .then(() => {
      showToast(msg || '📋 Скопировано!');
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success');
    })
    .catch(() => {
      const el = document.createElement('textarea');
      el.value = text; document.body.appendChild(el);
      el.select(); document.execCommand('copy');
      el.remove(); showToast(msg || '📋 Скопировано!');
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success');
    });
};

const toggleG = (head) => {
  const body = head.nextElementSibling;
  const arr = head.querySelector('.g-arrow');
  body.classList.toggle('open');
  arr.classList.toggle('open', body.classList.contains('open'));
  head.setAttribute('aria-expanded', body.classList.contains('open') ? 'true' : 'false');
  body.hidden = !body.classList.contains('open');
};

const openExternal = (url) => {
  const tg = window.Telegram?.WebApp;
  if (tg?.openLink) tg.openLink(url);
  else window.open(url, '_blank', 'noopener,noreferrer');
};

const openTelegram = () => {
  const url = 'https://t.me/fqof_bot';
  const tg = window.Telegram?.WebApp;
  if (tg?.openTelegramLink) tg.openTelegramLink(url);
  else window.location.href = url;
};

const initTelegramMiniApp = () => {
  const tg = window.Telegram?.WebApp;
  if (!tg) return;
  tg.ready();
  tg.expand();
  try {
    tg.setHeaderColor('#080b10');
    tg.setBackgroundColor('#080b10');
    tg.setBottomBarColor?.('#080b10');
  } catch (_) {}
};

async function fetchPing() {
  const dot = document.getElementById('ping-dot');
  const txt = document.getElementById('ping-text');
  if (!dot || !txt) return;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const r = await fetch('/api/ping', { signal: controller.signal, cache: 'no-store' });
    if (!r.ok) throw new Error('ping');
    const { ping_ms: ms } = await r.json();
    txt.textContent = ms + ' ms';
    dot.className = 'ping-dot ' + (ms < 100 ? 'good' : ms < 250 ? 'warn' : 'bad');
    dot.parentElement.title = 'Задержка соединения с сервером';
  } catch (_) {
    txt.textContent = 'нет связи';
    dot.className = 'ping-dot bad';
    dot.parentElement.title = 'Не удалось проверить соединение';
  } finally { clearTimeout(timeout); }
}

document.addEventListener('click', (event) => {
  const link = event.target.closest('a.dl-link');
  if (!link) return;
  event.preventDefault();
  openExternal(link.href);
});

initTelegramMiniApp();
