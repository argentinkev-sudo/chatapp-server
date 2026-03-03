require('dotenv').config();
console.log("ENV TEST =", process.env.MONGODB_URI);
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

const mongoose = require('mongoose');

const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: 'djugvj1zs',
  api_key: '738422473782157',
  api_secret: 'UdQ38-wXTI6jgXw8B5d4IQsdgAU'
});  

// Connexion MongoDB
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB connecté"))
  .catch(err => console.error("❌ Erreur MongoDB:", err));

// Schémas MongoDB
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null },
  role: { type: String, default: 'user' }
});

const messageSchema = new mongoose.Schema({
  channelId: String,
  username: String,
  avatar: String,
  content: String,
  fileUrl: String,
  fileName: String,
  type: String,
  edited: { type: Boolean, default: false },
  timestamp: { type: Number, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

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
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'Pseudo déjà pris' });
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash });
    const token = jwt.sign({ username }, JWT_SECRET);
    res.json({ token, username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Utilisateur inconnu' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Mauvais mot de passe' });
    const token = jwt.sign({ username }, JWT_SECRET);
    res.json({ token, username, avatar: user.avatar });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Upload avatar
app.post('/upload-avatar', upload.single('avatar'), async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ username: decoded.username });
    
    if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
    
    // Upload vers Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'chatapp_avatars',
      public_id: `${decoded.username}_${Date.now()}`,
      overwrite: true,
      resource_type: 'auto'
    });
    
    // Supprimer le fichier local temporaire
    fs.unlinkSync(req.file.path);
    
    // Sauvegarder l'URL Cloudinary dans la BDD
    user.avatar = result.secure_url;
    await user.save();
    
    res.json({ avatar: result.secure_url });
  } catch (err) {
    console.error('Erreur upload avatar:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Garde le reste tel quel
app.get('/channels', (req, res) => res.json(channels));


app.get('/channels', (req, res) => res.json(channels));
app.get('/messages/:channelId', async (req, res) => {
  try {
    const msgs = await Message.find({ channelId: req.params.channelId })
      .sort({ timestamp: -1 })
      .limit(100);
      
    res.json(msgs.reverse());
  } catch (err) {
    console.error(err);
    res.json([]);
  }
});

// Récupérer tous les utilisateurs (pour afficher EN LIGNE / HORS LIGNE)
app.get('/all-users', async (req, res) => {
  try {
    const allUsers = await User.find({}, 'username avatar');
    res.json(allUsers);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

// Routes Admin
app.get('/is-admin', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.json({ isAdmin: false });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ username: decoded.username });
    
    res.json({ isAdmin: user?.role === 'admin' });
  } catch (err) {
    res.json({ isAdmin: false });
  }
});

app.delete('/admin/delete-user/:username', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findOne({ username: decoded.username });
    
    if (admin?.role !== 'admin') return res.status(403).json({ error: 'Non autorisé' });
    
    await User.deleteOne({ username: req.params.username });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/admin/delete-message/:messageId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findOne({ username: decoded.username });
    
    if (admin?.role !== 'admin') return res.status(403).json({ error: 'Non autorisé' });
    
    await Message.findByIdAndDelete(req.params.messageId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
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

io.on('connection', async (socket) => {
  console.log(`✅ ${socket.username} connecté`);
  const user = await User.findOne({ username: socket.username });
  onlineUsers[socket.id] = { username: socket.username, avatar: user?.avatar || null };
  broadcastOnlineUsers();

  socket.on('join_channel', async (channelId) => {
  socket.rooms.forEach(r => { if (r !== socket.id) socket.leave(r); });
  socket.join(channelId);
  try {
    const msgs = await Message.find({ channelId }).sort({ timestamp: -1 }).limit(100);
    socket.emit('channel_history', msgs.reverse());
  } catch (err) {
    console.error(err);
    socket.emit('channel_history', []);
  }
});

  socket.on('send_message', async ({ channelId, content, fileUrl, fileName, type }) => {
  try {
    // Récupérer l'utilisateur pour avoir son avatar
    const user = await User.findOne({ username: socket.username });

    const msg = await Message.create({
      channelId,
      username: socket.username,
      avatar: user?.avatar || null,
      content,
      fileUrl,
      fileName,
      type: type || 'text',
      timestamp: Date.now()
    });
    io.emit('new_message', msg);  // Envoyer à tout le monde
  } catch (err) {
    console.error('Erreur save message:', err);
  }
});

// Éditer un message
socket.on('edit_message', async ({ messageId, newContent }) => {
  try {
    const msg = await Message.findById(messageId);
    if (!msg) return;
    if (msg.username !== socket.username) return;
    
    msg.content = newContent;
    msg.edited = true;
    await msg.save();
    
    io.emit('message_edited', { messageId, content: newContent, edited: true });
  } catch (err) {
    console.error('Erreur édition message:', err);
  }
});

// Supprimer un message
socket.on('delete_message', async ({ messageId }) => {
  try {
    const msg = await Message.findById(messageId);
    if (!msg) return;
    if (msg.username !== socket.username) return;
    
    await Message.findByIdAndDelete(messageId);
    io.emit('message_deleted', { messageId });
  } catch (err) {
    console.error('Erreur suppression message:', err);
  }
});

  socket.on('join_voice', async (channelId) => {
    if (!voiceRooms[channelId]) voiceRooms[channelId] = new Set();
    const user = await User.findOne({ username: socket.username });
    const peers = [...voiceRooms[channelId]];
    voiceRooms[channelId].add(socket.id);
    peers.forEach(peerId => io.to(peerId).emit('peer_joined', { peerId: socket.id, username: socket.username, avatar: user?.avatar || null }));
    socket.emit('voice_peers', peers.map(id => ({ peerId: id, username: onlineUsers[id]?.username, avatar: onlineUsers[id]?.avatar })));
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
  const users = Object.values(onlineUsers);
  io.emit('online_users', users);
}

  function broadcastVoiceRooms() {
  const state = {};
  Object.entries(voiceRooms).forEach(([cId, peers]) => {
    state[cId] = [...peers].map(id => ({
      username: onlineUsers[id]?.username,
      avatar: onlineUsers[id]?.avatar
    })).filter(u => u.username);
  });
    io.emit('voice_rooms_state', state);
  }
});

server.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));