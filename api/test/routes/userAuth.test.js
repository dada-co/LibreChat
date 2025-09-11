const express = require('express');
const request = require('supertest');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

jest.mock(
  '@librechat/data-schemas',
  () => ({
    logger: {
      warn: jest.fn(),
      info: jest.fn(),
      error: jest.fn(),
    },
  }),
  { virtual: true },
);

jest.mock(
  'librechat-data-provider',
  () => ({
    SystemRoles: { USER: 'user' },
  }),
  { virtual: true },
);

jest.mock('~/models', () => ({
  getUserById: jest.fn().mockResolvedValue({ _id: '123', role: 'user' }),
  updateUser: jest.fn(),
}));

const jwtStrategy = require('~/strategies/jwtStrategy');

const requireJwtAuth = (req, res, next) =>
  passport.authenticate('jwt', { session: false })(req, res, next);

const app = express();
app.use(cookieParser());
app.use(passport.initialize());
passport.use(jwtStrategy());

app.get('/api/user', requireJwtAuth, (req, res) => {
  res.status(200).json({ id: req.user.id });
});

describe('/api/user authentication', () => {
  it('returns 200 with Authorization header', async () => {
    const token = jwt.sign({ id: '123' }, process.env.JWT_SECRET);
    const res = await request(app)
      .get('/api/user')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe('123');
  });

  it('returns 200 with jwt cookie', async () => {
    const token = jwt.sign({ id: '123' }, process.env.JWT_SECRET);
    const res = await request(app)
      .get('/api/user')
      .set('Cookie', [`jwt=${token}`]);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe('123');
  });
});
