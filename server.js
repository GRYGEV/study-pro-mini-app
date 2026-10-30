const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});
const app = express();
app.use(express.json({ limit: '30kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function validateTelegramInitData(initData) {
  if (!initData || !process.env.BOT_TOKEN) return false;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return false;
  params.delete('hash');
  const dataCheckString = [...params.entries()].sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => `${k}=${v}`).join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(process.env.BOT_TOKEN).digest();
  const expected = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return false;
  const authDate = Number(params.get('auth_date') || 0);
  return authDate > 0 && (Date.now()/1000 - authDate) < 86400;
}


app.post('/api/order', async (req, res) => {
  try {
    const { service, name, details, deadline = '', contact = '', initData = '' } = req.body || {};

    if (!validateTelegramInitData(initData)) {
      return res.status(401).json({
        error: 'Не удалось проверить Telegram. Открой Mini App через бота.'
      });
    }

    if (![service, name, details].every(x => typeof x === 'string' && x.trim()) ||
        [service, name, details, deadline, contact].some(x => typeof x !== 'string' || x.length > 1500)) {
      return res.status(400).json({ error: 'Проверь заполнение полей.' });
    }

    const userData = new URLSearchParams(initData).get('user');
    let telegramId = '';

    try {
      telegramId = String(JSON.parse(userData || '{}').id || '');
    } catch (e) {}

    const text = [
      '📩 Новая заявка STUDY PRO',
      `Услуга: ${service.trim()}`,
      `Имя: ${name.trim()}`,
      `Описание: ${details.trim()}`,
      `Срок: ${deadline.trim() || 'не указан'}`,
      `Контакт: ${contact.trim() || 'не указан'}`,
      `Telegram ID: ${telegramId || 'не получен'}`
    ].join('\n');

    const response = await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: process.env.ADMIN_CHAT_ID,
        text
      })
    });

    const result = await response.json();

    if (!result.ok) throw new Error('Telegram sendMessage failed');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'Не удалось передать заявку администратору.' });
  }
});


app.post('/telegram-webhook', async (req, res) => {
  try {
    const secret = req.get('X-Telegram-Bot-Api-Secret-Token');

    if (!process.env.WEBHOOK_SECRET ||
        secret !== process.env.WEBHOOK_SECRET) {
      return res.sendStatus(403);
    }

    const message = req.body?.message;

    if (!message ||
        String(message.chat?.id) !== String(process.env.ADMIN_CHAT_ID)) {
      return res.sendStatus(200);
    }

    if (!message.document) return res.sendStatus(200);

    const originalText = message.reply_to_message?.text || '';
    const match = originalText.match(/Telegram ID:\s*(\d+)/);

    if (!match) {
      await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: process.env.ADMIN_CHAT_ID,
          text: 'Не удалось найти Telegram ID. Ответь именно на уведомление о заявке.'
        })
      });
      return res.sendStatus(200);
    }

    const customerId = match[1];

    const sent = await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendDocument`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: customerId,
        document: message.document.file_id,
        caption: '📎 Ваш готовый файл от STUDY PRO!'
      })
    });

    const result = await sent.json();

    await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: process.env.ADMIN_CHAT_ID,
        text: result.ok
          ? '✅ Файл отправлен клиенту!'
          : '❌ Не удалось отправить файл клиенту. Проверь, что клиент запускал бота.'
      })
    });

    return res.sendStatus(200);
  } catch (error) {
    console.error(error);
    return res.sendStatus(200);
  }
});

app.get('/health', (_, res) => res.send('STUDY PRO is running'));

const port = process.env.PORT || 3000;

app.listen(port, async () => {
  console.log(`STUDY PRO listening on ${port}`);

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${process.env.BOT_TOKEN}/setWebhook`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://study-pro-mini-app.onrender.com/telegram-webhook',
          secret_token: process.env.WEBHOOK_SECRET,
          allowed_updates: ['message']
        })
      }
    );

    const result = await response.json();
    console.log('Webhook setup:', result.ok ? 'success' : result.description);
  } catch (error) {
    console.error('Webhook setup failed:', error);
  }
});

