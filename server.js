const express = require('express');
const crypto = require('crypto');
const path = require('path');

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

app.post('/api/order', async (req,res) => {
  const {service,name,details,deadline='',contact='',initData=''} = req.body || {};
  if (!validateTelegramInitData(initData)) return res.status(401).json({error:'Не удалось проверить Telegram. Открой Mini App через бота.'});
  if (![service,name,details].every(x => typeof x === 'string' && x.trim()) ||
      [service,name,details,deadline,contact].some(x => typeof x !== 'string' || x.length > 1500)) {
    return res.status(400).json({error:'Проверь заполнение полей.'});
  }
  const text = [
    '📩 Новая заявка STUDY PRO',
    `Услуга: ${service.trim()}`,
    `Имя: ${name.trim()}`,
    `Описание: ${details.trim()}`,
    `Срок: ${deadline.trim() || 'не указан'}`,
    `Контакт: ${contact.trim() || 'не указан'}`
  ].join('\n');
  try {
    const response = await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({chat_id:process.env.ADMIN_CHAT_ID,text})
    });
    const result = await response.json();
    if (!result.ok) throw new Error('Telegram sendMessage failed');
    res.json({ok:true});
  } catch (e) { console.error(e); res.status(502).json({error:'Не удалось передать заявку администратору.'}); }
});

app.get('/health', (_,res)=>res.send('STUDY PRO is running'));
const port = process.env.PORT || 3000;
app.listen(port, ()=>console.log(`STUDY PRO listening on ${port}`));
