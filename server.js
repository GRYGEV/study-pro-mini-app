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



function adminToken(timestamp) {
  return crypto
    .createHmac('sha256', process.env.ADMIN_PASSWORD)
    .update(timestamp)
    .digest('hex');
}

function isAdmin(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)sp_admin=(\d+)\.([a-f0-9]+)/);

  if (!match) return false;

  const timestamp = match[1];
  const signature = match[2];

  if (Date.now() - Number(timestamp) > 12 * 60 * 60 * 1000) {
    return false;
  }

  const expected = adminToken(timestamp);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post('/api/admin/login', (req, res) => {
  const password = req.body?.password || '';
  const savedPassword = process.env.ADMIN_PASSWORD || '';

  if (!savedPassword) {
    return res.status(500).json({ error: 'Пароль администратора не настроен.' });
  }

  const a = Buffer.from(String(password));
  const b = Buffer.from(savedPassword);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Неверный пароль.' });
  }

  const timestamp = String(Date.now());
  const signature = adminToken(timestamp);

  res.setHeader(
    'Set-Cookie',
    `sp_admin=${timestamp}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=43200`
  );

  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    'sp_admin=; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=0'
  );
  res.json({ ok: true });
});
app.get('/api/admin/orders', async (req, res) => {
  if (!isAdmin(req)) return res.sendStatus(401);

  try {
    const result = await pool.query(`
      SELECT id, order_number, service, customer_name,
             details, deadline, status, created_at
      FROM orders
      ORDER BY created_at DESC
    `);

    res.json({ orders: result.rows });
  } catch (error) {
    console.error('Admin orders error:', error);
    res.status(500).json({ error: 'Не удалось загрузить заказы.' });
  }
});


app.patch('/api/admin/orders/:id/status', async (req, res) => {
  if (!isAdmin(req)) return res.sendStatus(401);

  const allowedStatuses = ['Новая', 'В работе', 'Готово', 'Отправлено'];
  const { status } = req.body || {};

  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Недопустимый статус.' });
  }

  try {
    const result = await pool.query(
      `UPDATE orders
       SET status = $1
       WHERE id = $2
       RETURNING id, order_number, status, telegram_id`,
      [status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Заказ не найден.' });
    }

    const order = result.rows[0];
    let notificationSent = false;

    try {
      const response = await fetch(
        `https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: order.telegram_id,
            text: [
              '📦 Обновление заказа STUDY PRO',
              `Заказ: ${order.order_number}`,
              `Новый статус: ${order.status}`
            ].join('\n')
          })
        }
      );

      const telegramResult = await response.json();
      notificationSent = telegramResult.ok === true;
    } catch (telegramError) {
      console.error('Customer notification error:', telegramError);
    }

    res.json({
      ok: true,
      order: {
        id: order.id,
        order_number: order.order_number,
        status: order.status
      },
      notificationSent
    });
  } catch (error) {
    console.error('Admin status error:', error);
    res.status(500).json({ error: 'Не удалось изменить статус.' });
  }
});

app.delete('/api/admin/orders/:id', async (req, res) => {
  if (!isAdmin(req)) return res.sendStatus(401);

  try {
    const result = await pool.query(
      'DELETE FROM orders WHERE id = $1 RETURNING id',
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Заказ не найден.' });
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Delete order error:', error);
    res.status(500).json({ error: 'Не удалось удалить заказ.' });
  }
});

app.post('/api/order', async (req, res) => {
  try {
    const { service, name, details, deadline = '', initData, consent } = req.body;

    if (!validateTelegramInitData(initData)) {
      return res.status(401).json({
        error: 'Не удалось проверить Telegram. Открой Mini App через бота.'
      });
    }

    if (![service, name, details].every(x => typeof x === 'string' && x.trim()) ||
        [service, name, details, deadline].some(x => typeof x !== 'string' || x.length > 1500)) {
      return res.status(400).json({ error: 'Проверь заполнение полей.' });
    }

    
const userData = new URLSearchParams(initData).get('user');
let telegramId = '';

try {
  telegramId = String(JSON.parse(userData || '{}').id || '');
} catch (e) {}

if (!telegramId) {
  return res.status(400).json({ error: 'Не удалось получить Telegram ID.' });
}
if (consent !== true) {
  return res.status(400).json({
    error: 'Необходимо дать согласие на обработку персональных данных.'
  });
}

const orderResult = await pool.query(
  `WITH next_id AS (
     SELECT nextval('orders_id_seq') AS id
   )
   INSERT INTO orders
     (id, order_number, telegram_id, service, customer_name, details, deadline)
   SELECT
     id,
     'SP-' || LPAD(id::text, 4, '0'),
     $1, $2, $3, $4, $5
   FROM next_id
   RETURNING order_number`,
  [telegramId, service.trim(), name.trim(), details.trim(), deadline.trim()]
);


const orderNumber = orderResult.rows[0].order_number;

const text = [
  '📩 Новая заявка STUDY PRO',
  `Заказ: ${orderNumber}`,
  `Услуга: ${service.trim()}`,
  `Имя: ${name.trim()}`,
  `Описание: ${details.trim()}`,
  `Срок: ${deadline.trim() || 'не указан'}`,
  `Контакт: ${contact.trim() || 'не указан'}`,
  `Telegram ID: ${telegramId}`
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

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      order_number TEXT UNIQUE NOT NULL,
      telegram_id TEXT NOT NULL,
      service TEXT NOT NULL,
      customer_name TEXT NOT NULL,
      details TEXT NOT NULL,
      deadline TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Добавляем колонку со статусом заказа
  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Новая'
  `);

  console.log('STUDY PRO database ready');
}
app.get('/health', (_, res) => res.send('STUDY PRO is running'));

const port = process.env.PORT || 3000;


app.listen(port, async () => {
  console.log(`STUDY PRO listening on ${port}`);

  try {
    await initDatabase();
    console.log('STUDY PRO database ready');
  } catch (error) {
    console.error('Database initialization failed:', error);
  }

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

