const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname)));

function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, name, surname, email, created_at FROM users WHERE id = ?', [id], (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

app.post('/api/register', async (req, res) => {
  try {
    const { name, surname, email, password } = req.body;
    if (!name || !surname || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row) return res.status(400).json({ error: 'Email already registered' });

      const hash = await bcrypt.hash(password, 10);
      db.run('INSERT INTO users (name, surname, email, password_hash) VALUES (?, ?, ?, ?)', [name, surname, email, hash], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create user' });
        req.session.userId = this.lastID;
        getUserById(this.lastID).then(user => res.json({ user })).catch(e => res.status(500).json({ error: 'User lookup failed' }));
      });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  db.get('SELECT id, name, surname, email, password_hash FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    req.session.userId = row.id;
    res.json({ user: { id: row.id, name: row.name, surname: row.surname, email: row.email } });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const user = await getUserById(req.session.userId);
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});


app.get('/api/posts', (req, res) => {
  const sql = `SELECT posts.id, posts.content, posts.created_at, users.id as user_id, users.name, users.surname
               FROM posts JOIN users ON posts.user_id = users.id
               ORDER BY posts.created_at DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ posts: rows });
  });
});

app.post('/api/posts', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Empty content' });

  db.run('INSERT INTO posts (user_id, content) VALUES (?, ?)', [req.session.userId, content.trim()], function(err) {
    if (err) return res.status(500).json({ error: 'DB insert failed' });
    const postId = this.lastID;
    db.get('SELECT posts.id, posts.content, posts.created_at, users.id as user_id, users.name, users.surname FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = ?', [postId], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB lookup failed' });
      res.json({ post: row });
    });
  });
});


app.delete('/api/posts/:id', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const postId = req.params.id;
  db.get('SELECT user_id FROM posts WHERE id = ?', [postId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Post not found' });
    if (row.user_id !== req.session.userId) return res.status(403).json({ error: 'Not allowed' });

    db.run('DELETE FROM posts WHERE id = ?', [postId], function(err) {
      if (err) return res.status(500).json({ error: 'Delete failed' });
      res.json({ ok: true });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
