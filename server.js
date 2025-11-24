// backend/server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();

// Render (and other hosts) use process.env.PORT
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'super-secret-key-change-this'; // change in production

// Middleware
app.use(cors());
app.use(bodyParser.json());

// ---- In-memory "database" ----
let users = [];
let games = [
  {
    id: 'g1',
    title: 'Code Relay',
    category: 'Coding',
    description: 'Team-based coding contest with relay-style problem solving.',
    maxParticipants: 100,
    teamSize: 2,
    venue: 'Lab 1',
    dateTime: 'Day 1, 10:00 AM',
    isActive: true
  },
  {
    id: 'g2',
    title: 'LAN Gaming - Valorant',
    category: 'Esports',
    description: '5v5 Valorant tournament in LAN setup.',
    maxParticipants: 50,
    teamSize: 5,
    venue: 'Lab 2',
    dateTime: 'Day 2, 2:00 PM',
    isActive: true
  },
  {
    id: 'g3',
    title: 'Blind Coding',
    category: 'Coding',
    description: 'Code without seeing the screen. Fun and challenging!',
    maxParticipants: 40,
    teamSize: 1,
    venue: 'Lab 3',
    dateTime: 'Day 1, 3:00 PM',
    isActive: true
  }
];

let participations = []; // { id, userId, gameId, status, createdAt }

// Seed one admin user (password: admin123)
(async () => {
  const hash = await bcrypt.hash('admin123', 10);
  users.push({
    id: 'u1',
    name: 'Admin User',
    rollNumber: 'ADMIN-000',
    year: 'N/A',
    stream: 'Admin',
    email: 'admin@techfest.com',
    mobile: '9999999999',
    passwordHash: hash,
    role: 'admin',
    authProvider: 'local',
    createdAt: new Date().toISOString()
  });
})();

// ---- Helper functions ----
function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2) return res.status(401).json({ message: 'Token error' });

  const [scheme, token] = parts;
  if (!/^Bearer$/i.test(scheme)) return res.status(401).json({ message: 'Token malformatted' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token invalid' });
    req.user = decoded;
    return next();
  });
}

function adminMiddleware(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin only' });
  }
  next();
}

// ---- Auth Routes ----

// Sign up (RELAXED validation)
app.post('/api/auth/signup', async (req, res) => {
  let { name, rollNumber, year, stream, email, mobile, password } = req.body || {};

  // Normalize / trim
  name = (name || '').trim();
  rollNumber = (rollNumber || '').trim();
  year = (year || '').trim();
  stream = (stream || '').trim();
  email = (email || '').trim();
  mobile = (mobile || '').trim();

  // Only these are STRICTLY required on backend
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ message: 'Name, email and password are required' });
  }

  const lowerEmail = email.toLowerCase();

  // Check duplicates only when values are present
  const existing = users.find((u) => {
    if (u.email && u.email.toLowerCase() === lowerEmail) return true;
    if (mobile && u.mobile === mobile) return true;
    if (
      rollNumber &&
      u.rollNumber &&
      u.rollNumber.toLowerCase() === rollNumber.toLowerCase()
    ) {
      return true;
    }
    return false;
  });

  if (existing) {
    return res.status(400).json({
      message: 'A user with this email, mobile, or roll number already exists'
    });
  }

  const hash = await bcrypt.hash(password, 10);
  const newUser = {
    id: 'u' + (users.length + 1),
    name,
    rollNumber,
    year,
    stream,
    email,
    mobile,
    passwordHash: hash,
    role: 'user',
    authProvider: 'local',
    createdAt: new Date().toISOString()
  };

  users.push(newUser);

  const token = createToken(newUser);
  res.json({ token });
});

// Login with email or mobile or roll number
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  const lowerId = identifier.toLowerCase();
  const user = users.find(
    (u) =>
      (u.email && u.email.toLowerCase() === lowerId) ||
      u.mobile === identifier ||
      u.rollNumber === identifier
  );
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(400).json({ message: 'Incorrect password' });
  }

  const token = createToken(user);
  res.json({ token });
});

// Current user (JWT payload only)
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ---- User Profile Routes ----

// Get full profile of current user
app.get('/api/users/me', authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  const safeUser = {
    id: user.id,
    name: user.name,
    rollNumber: user.rollNumber,
    year: user.year,
    stream: user.stream,
    email: user.email,
    mobile: user.mobile,
    role: user.role,
    createdAt: user.createdAt
  };
  res.json({ user: safeUser });
});

// Update profile (name, mobile, year, stream)
app.patch('/api/users/me', authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  const { name, mobile, year, stream } = req.body;

  if (name && typeof name === 'string') user.name = name.trim();
  if (mobile && typeof mobile === 'string') user.mobile = mobile.trim();
  if (year && typeof year === 'string') user.year = year.trim();
  if (stream && typeof stream === 'string') user.stream = stream.trim();

  const safeUser = {
    id: user.id,
    name: user.name,
    rollNumber: user.rollNumber,
    year: user.year,
    stream: user.stream,
    email: user.email,
    mobile: user.mobile,
    role: user.role,
    createdAt: user.createdAt
  };
  res.json({ user: safeUser });
});

// ---- Games Routes ----

// List all games
app.get('/api/games', (req, res) => {
  res.json({ games });
});

// ---- Participation Routes ----

// Get participations of current user
app.get('/api/participation/my', authMiddleware, (req, res) => {
  const myParts = participations.filter((p) => p.userId === req.user.id);
  res.json({ participations: myParts });
});

// Register for a game
app.post('/api/participation', authMiddleware, (req, res) => {
  const { gameId } = req.body;
  if (!gameId) {
    return res.status(400).json({ message: 'gameId required' });
  }

  const game = games.find((g) => g.id === gameId);
  if (!game) {
    return res.status(400).json({ message: 'Game not found' });
  }

  const existing = participations.find((p) => p.userId === req.user.id && p.gameId === gameId);
  if (existing) {
    return res.status(400).json({ message: 'Already registered in this game' });
  }

  const part = {
    id: 'p' + (participations.length + 1),
    userId: req.user.id,
    gameId,
    status: 'registered',
    createdAt: new Date().toISOString()
  };
  participations.push(part);

  res.json({ participation: part });
});

// Cancel participation
app.delete('/api/participation/:id', authMiddleware, (req, res) => {
  const id = req.params.id;
  const part = participations.find((p) => p.id === id);

  if (!part) {
    return res.status(404).json({ message: 'Participation not found' });
  }

  if (part.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Not allowed' });
  }

  participations = participations.filter((p) => p.id !== id);
  res.json({ message: 'Cancelled' });
});

// ---- Admin Routes ----

// List all users with details + stats
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const safeUsers = users.map((u) => {
    const userParts = participations.filter((p) => p.userId === u.id);
    return {
      id: u.id,
      name: u.name,
      rollNumber: u.rollNumber,
      year: u.year,
      stream: u.stream,
      email: u.email,
      mobile: u.mobile,
      role: u.role,
      createdAt: u.createdAt,
      participationsCount: userParts.length
    };
  });
  res.json({ users: safeUsers });
});

// List all participations enriched
app.get('/api/admin/participations', authMiddleware, adminMiddleware, (req, res) => {
  const enriched = participations.map((p) => {
    const user = users.find((u) => u.id === p.userId) || {};
    const game = games.find((g) => g.id === p.gameId) || {};
    return {
      id: p.id,
      gameId: p.gameId,
      gameTitle: game.title || '',
      userId: p.userId,
      userName: user.name || '',
      userEmail: user.email || '',
      userMobile: user.mobile || '',
      userRoll: user.rollNumber || '',
      userYear: user.year || '',
      userStream: user.stream || '',
      status: p.status,
      createdAt: p.createdAt
    };
  });
  res.json({ participations: enriched });
});

// Export participations CSV
app.get('/api/admin/export', (req, res) => {
  const { token, gameId } = req.query;
  if (!token) return res.status(401).send('Token required');

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).send('Invalid token');
  }

  if (!decoded || decoded.role !== 'admin') {
    return res.status(403).send('Admin only');
  }

  let rows = participations;
  if (gameId) rows = rows.filter((p) => p.gameId === gameId);

  const header = [
    'Game',
    'User',
    'Email',
    'Mobile',
    'RollNumber',
    'Year',
    'Stream',
    'Status',
    'RegisteredAt'
  ];
  const csv = [
    header.join(','),
    ...rows.map((p) => {
      const user = users.find((u) => u.id === p.userId) || {};
      const game = games.find((g) => g.id === p.gameId) || {};
      return [
        game.title || '',
        user.name || '',
        user.email || '',
        user.mobile || '',
        user.rollNumber || '',
        user.year || '',
        user.stream || '',
        p.status,
        p.createdAt
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(',');
    })
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="participations.csv"');
  res.send(csv);
});

// Export USERS CSV
app.get('/api/admin/users/export', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(401).send('Token required');

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).send('Invalid token');
  }

  if (!decoded || decoded.role !== 'admin') {
    return res.status(403).send('Admin only');
  }

  const header = [
    'Name',
    'RollNumber',
    'Year',
    'Stream',
    'Email',
    'Mobile',
    'Role',
    'JoinedAt',
    'RegistrationsCount'
  ];

  const csv = [
    header.join(','),
    ...users.map((u) => {
      const userParts = participations.filter((p) => p.userId === u.id);
      return [
        u.name || '',
        u.rollNumber || '',
        u.year || '',
        u.stream || '',
        u.email || '',
        u.mobile || '',
        u.role || '',
        u.createdAt || '',
        userParts.length
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(',');
    })
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="users.csv"`);
  res.send(csv);
});

// ---- Start server ----
app.listen(PORT, () => {
  console.log(`TechFest backend running on port ${PORT}`);
});
