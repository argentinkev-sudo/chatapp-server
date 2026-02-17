const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  maxHttpBufferSize: 50e6
});

const JWT_SECRET = process.env.JWT_SECRET || 'chatapp_secret_key';
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

const users = {};
const channels = {
  text: [
    { id: 'general', name: '💬 général', type: 'text' },
    { id: 'blagues', name: '😂 blagues', type: 'text' },
    { id: 'jeux', name: '🎮 jeux', type: 'text' }
  ],
  voice: [
    { id: 'vocal1', name: '🔊 Vocal 1', type: 'voice' },
    { id: 'vocal2', name: '🔊 Vocal 2', type: 'voice' },
    { id: 'stream', name: '📺 Stream', type: 'voice' }
  ]
};
const messages = {};
const onlineUsers = {};
const voiceRooms = {};

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Pas de fichier' });
  res.json({ url: `/uploads/${req.file.filename}`, name: req.file.originalname });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (users[username]) return res.status(400).json({ error: 'Pseudo déjà pris' });
  const hash = await bcrypt.hash(password, 10);
  users[username] = { password: hash };
  const token = jwt.sign({ username }, JWT_SECRET);
  res.json({ token, username });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user) return res.status(401).json({ error: 'Utilisateur inconnu' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Mauvais mot de passe' });
  const token = jwt.sign({ username }, JWT_SECRET);
  res.json({ token, username });
});

app.get('/channels', (req, res) => res.json(channels));
app.get('/messages/:channelId', (req, res) => {
  res.json((messages[req.params.channelId] || []).slice(-100));
});

io.use((socket, next) => {
  try {
    const decoded = jwt.verify(socket.handshake.auth.token, JWT_SECRET);
    socket.username = decoded.username;
    next();
  } catch {
    next(new Error('Non autorisé'));
  }
});

io.on('connection', (socket) => {
  console.log(`✅ ${socket.username} connecté`);
  onlineUsers[socket.id] = { username: socket.username };
  broadcastOnlineUsers();

  socket.on('join_channel', (channelId) => {
    socket.rooms.forEach(r => { if (r !== socket.id) socket.leave(r); });
    socket.join(channelId);
    socket.emit('channel_history', (messages[channelId] || []).slice(-100));
  });

  socket.on('send_message', ({ channelId, content, fileUrl, fileName, type }) => {
    const msg = { id: uuidv4(), username: socket.username, content, fileUrl, fileName, type: type || 'text', timestamp: Date.now() };
    if (!messages[channelId]) messages[channelId] = [];
    messages[channelId].push(msg);
    if (messages[channelId].length > 500) messages[channelId].shift();
    io.to(channelId).emit('new_message', msg);
  });

  socket.on('join_voice', (channelId) => {
    if (!voiceRooms[channelId]) voiceRooms[channelId] = new Set();
    const peers = [...voiceRooms[channelId]];
    voiceRooms[channelId].add(socket.id);
    peers.forEach(peerId => io.to(peerId).emit('peer_joined', { peerId: socket.id, username: socket.username }));
    socket.emit('voice_peers', peers.map(id => ({ peerId: id, username: onlineUsers[id]?.username })));
    broadcastVoiceRooms();
  });

  socket.on('leave_voice', (channelId) => {
    if (voiceRooms[channelId]) {
      voiceRooms[channelId].delete(socket.id);
      voiceRooms[channelId].forEach(peerId => io.to(peerId).emit('peer_left', { peerId: socket.id }));
    }
    broadcastVoiceRooms();
  });

  socket.on('signal', ({ to, signal }) => {
    io.to(to).emit('signal', { from: socket.id, signal });
  });

  socket.on('disconnect', () => {
    console.log(`❌ ${socket.username} déconnecté`);
    Object.entries(voiceRooms).forEach(([cId, peers]) => {
      if (peers.has(socket.id)) {
        peers.delete(socket.id);
        peers.forEach(peerId => io.to(peerId).emit('peer_left', { peerId: socket.id }));
      }
    });
    delete onlineUsers[socket.id];
    broadcastOnlineUsers();
    broadcastVoiceRooms();
  });

  function broadcastOnlineUsers() {
    const unique = [...new Set(Object.values(onlineUsers).map(u => u.username))];
    io.emit('online_users', unique);
  }

  function broadcastVoiceRooms() {
    const state = {};
    Object.entries(voiceRooms).forEach(([cId, peers]) => {
      state[cId] = [...peers].map(id => onlineUsers[id]?.username).filter(Boolean);
    });
    io.emit('voice_rooms_state', state);
  }
});

server.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));