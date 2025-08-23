// config/make-magic-link.js
require('dotenv').config();
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

(async () => {
  const MONGO = process.env.MONGO_URI || process.env.MONGODB_URI;
  const MAGIC_SECRET = process.env.MAGIC_LINK_SECRET || process.env.JWT_SECRET;
  const PUBLIC_URL = process.env.PUBLIC_URL;

  if (!MONGO) throw new Error('MONGO_URI not set');
  if (!MAGIC_SECRET) throw new Error('MAGIC_LINK_SECRET (or JWT_SECRET) not set');
  if (!PUBLIC_URL) throw new Error('PUBLIC_URL not set');

  await mongoose.connect(MONGO, {});
  const User = mongoose.model('User', new mongoose.Schema({}, { strict: false, collection: 'users' }));

  // very simple arg parsing: --email ... OR --userId ... [--ttl 30d]
  const args = process.argv.slice(2);
  const get = (k, d) => {
    const i = args.indexOf(k);
    return i >= 0 ? args[i + 1] : d;
  };
  const email = get('--email');
  const userId = get('--userId');
  const ttl = get('--ttl', '30d');

  if (!email && !userId) {
    console.error('Usage: node config/make-magic-link.js --email someone@x.com [--ttl 30d]');
    console.error('   or: node config/make-magic-link.js --userId <mongo_id> [--ttl 30d]');
    process.exit(1);
  }

  const user = userId
    ? await User.findById(userId)
    : await User.findOne({ email: String(email).toLowerCase() });

  if (!user) {
    console.error('User not found');
    process.exit(2);
  }

  const token = jwt.sign(
    { sub: String(user._id), typ: 'magic' },
    MAGIC_SECRET,
    { expiresIn: ttl, audience: 'magic-link' },
  );

  const url = `${PUBLIC_URL}/m/${token}`;
  console.log(JSON.stringify({ url, userId: user._id }, null, 2));
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
