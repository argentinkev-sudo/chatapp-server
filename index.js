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
  role: { type: String, default: 'user' },
   bio: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  friends: { type: Array, default: [] }
});

const messageSchema = new mongoose.Schema({
  channelId: String,
  username: String,
  avatar: String,
  role: { type: String, default: 'user' },
  content: String,
  fileUrl: String,
  fileName: String,
  type: String,
  edited: { type: Boolean, default: false },
  reactions: { type: Array, default: [] },
  timestamp: { type: Number, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

const friendRequestSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'accepted', 'rejected'], 
    default: 'pending' 
  },
  createdAt: { type: Date, default: Date.now }
});

const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

const privateMessageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  content: { type: String, required: true },
  edited: { type: Boolean, default: false },
  timestamp: { type: Number, default: Date.now }
});

const PrivateMessage = mongoose.model('PrivateMessage', privateMessageSchema);

const channelSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  type: { type: String, enum: ['text', 'voice'], required: true },
  createdAt: { type: Date, default: Date.now }
});
const Channel = mongoose.model('Channel', channelSchema);

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


app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Pas de fichier' });
    
    // Upload vers Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'chatapp_files',
      public_id: `file_${Date.now()}`,
      resource_type: 'auto'  // Supporte images, GIFs, vidéos
    });
    
    // Supprimer le fichier temporaire local
    const fs = require('fs');
    fs.unlinkSync(req.file.path);
    
    res.json({ 
      url: result.secure_url,  // URL Cloudinary
      name: req.file.originalname 
    });
  } catch (err) {
    console.error('Erreur upload Cloudinary:', err);
    res.status(500).json({ error: 'Erreur upload' });
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

app.get('/channels', async (req, res) => {
  try {
    let textChannels = await Channel.find({ type: 'text' }).sort({ createdAt: 1 });
    let voiceChannels = await Channel.find({ type: 'voice' }).sort({ createdAt: 1 });

    // Créer les salons par défaut si la base est vide
    if (textChannels.length === 0 && voiceChannels.length === 0) {
      await Channel.insertMany([
        { id: 'general', name: '💬 général', type: 'text' },
        { id: 'blagues', name: '😂 blagues', type: 'text' },
        { id: 'jeux', name: '🎮 jeux', type: 'text' },
        { id: 'vocal1', name: '🔊 Vocal 1', type: 'voice' },
        { id: 'vocal2', name: '🔊 Vocal 2', type: 'voice' },
        { id: 'stream', name: '📺 Stream', type: 'voice' }
      ]);
      textChannels = await Channel.find({ type: 'text' }).sort({ createdAt: 1 });
      voiceChannels = await Channel.find({ type: 'voice' }).sort({ createdAt: 1 });
    }

    res.json({ text: textChannels, voice: voiceChannels });
  } catch (err) {
    console.error(err);
    res.status(500).json({ text: [], voice: [] });
  }
});

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
    const allUsers = await User.find({}, 'username avatar role bio createdAt');
    res.json(allUsers);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
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
    
    if (!admin || (admin.role !== 'admin' && admin.role !== 'moderator')) {
  return res.status(403).json({ error: 'Non autorisé' });
}
    
    await Message.findByIdAndDelete(req.params.messageId);
    io.emit('message_deleted', { messageId: req.params.messageId });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Changer le rôle d'un utilisateur
app.post('/admin/change-role', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findOne({ username: decoded.username });
    
    if (admin?.role !== 'admin') return res.status(403).json({ error: 'Non autorisé' });
    
    const { username, role } = req.body;
    if (!['admin', 'moderator', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Rôle invalide' });
    }
    
    await User.updateOne({ username }, { role });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Ajouter une réaction
app.post('/add-reaction', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { messageId, emoji } = req.body;
    
    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ error: 'Message introuvable' });
    
    // Chercher si l'emoji existe déjà
    const reactionIndex = message.reactions.findIndex(r => r.emoji === emoji);
    
    if (reactionIndex >= 0) {
      // L'emoji existe, ajouter l'utilisateur s'il n'y est pas déjà
      if (!message.reactions[reactionIndex].users.includes(decoded.username)) {
        message.reactions[reactionIndex].users.push(decoded.username);
        message.markModified('reactions');
      }
    } else {
      // Nouvel emoji
      message.reactions.push({ emoji, users: [decoded.username] });
      message.markModified('reactions');
    }
    
    await message.save();
    io.emit('reaction_updated', { messageId, reactions: message.reactions });
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Retirer une réaction
app.post('/remove-reaction', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { messageId, emoji } = req.body;
    
    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ error: 'Message introuvable' });
    
    const reactionIndex = message.reactions.findIndex(r => r.emoji === emoji);
    
    if (reactionIndex >= 0) {
      // Retirer l'utilisateur
      message.reactions[reactionIndex].users = message.reactions[reactionIndex].users.filter(u => u !== decoded.username);
      
      // Si plus personne n'a cette réaction, supprimer l'emoji
      if (message.reactions[reactionIndex].users.length === 0) {
        message.reactions.splice(reactionIndex, 1);
      }
    }
    
    await message.save();
    io.emit('reaction_updated', { messageId, reactions: message.reactions });
    
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

// Créer un salon (admin only)
app.post('/admin/create-channel', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findOne({ username: decoded.username });
    if (admin?.role !== 'admin') return res.status(403).json({ error: 'Non autorisé' });

    const { name, type } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'Nom et type requis' });

    const id = name.toLowerCase().replace(/[^a-z0-9]/g, '-') + '-' + Date.now();
    const channel = await Channel.create({ id, name, type });

    io.emit('channel_created', channel);
    res.json({ success: true, channel });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Supprimer un salon (admin only)
app.delete('/admin/delete-channel/:channelId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await User.findOne({ username: decoded.username });
    if (admin?.role !== 'admin') return res.status(403).json({ error: 'Non autorisé' });

    await Channel.deleteOne({ id: req.params.channelId });
    io.emit('channel_deleted', { channelId: req.params.channelId });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/update-bio', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { bio } = req.body;

    console.log('📝 Mise à jour bio pour:', decoded.username, '- Bio:', bio);
    
    await User.findOneAndUpdate(
      { username: decoded.username },
      { bio: bio }
    );
    
    console.log('✅ Bio sauvegardée !');
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Envoyer une demande d'ami
app.post('/send-friend-request', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { targetUsername } = req.body;
    
    // Vérifier si l'utilisateur existe
    const targetUser = await User.findOne({ username: targetUsername });
    if (!targetUser) return res.status(404).json({ error: 'Utilisateur introuvable' });
    
    // Vérifier si déjà ami
    const user = await User.findOne({ username: decoded.username });
    if (user.friends.includes(targetUsername)) {
      return res.status(400).json({ error: 'Déjà ami' });
    }
    
    // Vérifier si demande déjà envoyée
    const existing = await FriendRequest.findOne({
      from: decoded.username,
      to: targetUsername,
      status: 'pending'
    });
    if (existing) return res.status(400).json({ error: 'Demande déjà envoyée' });
    
    // Créer la demande
    await FriendRequest.create({
      from: decoded.username,
      to: targetUsername
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Accepter une demande d'ami
app.post('/accept-friend-request', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { requestId } = req.body;
    
    const request = await FriendRequest.findById(requestId);
    if (!request || request.to !== decoded.username) {
      return res.status(404).json({ error: 'Demande introuvable' });
    }
    
    // Marquer comme acceptée
    request.status = 'accepted';
    await request.save();
    
    // Ajouter aux listes d'amis
    await User.findOneAndUpdate(
      { username: request.from },
      { $addToSet: { friends: request.to } }
    );
    await User.findOneAndUpdate(
      { username: request.to },
      { $addToSet: { friends: request.from } }
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Refuser une demande d'ami
app.post('/reject-friend-request', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { requestId } = req.body;
    
    const request = await FriendRequest.findById(requestId);
    if (!request || request.to !== decoded.username) {
      return res.status(404).json({ error: 'Demande introuvable' });
    }
    
    // Supprimer la demande
    await FriendRequest.findByIdAndDelete(requestId);
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Récupérer demandes et amis
app.get('/my-friends', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Demandes reçues
    const requests = await FriendRequest.find({
      to: decoded.username,
      status: 'pending'
    });
    
    // Liste d'amis
    const user = await User.findOne({ username: decoded.username });
    const friendsList = await User.find({ username: { $in: user.friends } }, 'username avatar');
    
    res.json({ requests, friends: friendsList });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Envoyer un MP
app.post('/send-pm', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { to, content } = req.body;
    
    const pm = await PrivateMessage.create({
      from: decoded.username,
      to: to,
      content: content
    });
    
    res.json({ success: true, message: pm.toObject() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Charger l'historique MP avec un ami
app.post('/load-pm', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { friendUsername } = req.body;
    
    // Charger tous les messages entre les 2 utilisateurs
    const messages = await PrivateMessage.find({
      $or: [
        { from: decoded.username, to: friendUsername },
        { from: friendUsername, to: decoded.username }
      ]
    }).sort({ timestamp: 1 });
    
    res.json(messages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Éditer un MP
app.post('/edit-pm', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { messageId, newContent } = req.body;
    
    const msg = await PrivateMessage.findById(messageId);
    if (!msg || msg.from !== decoded.username) {
      return res.status(403).json({ error: 'Non autorisé' });
    }
    
    msg.content = newContent;
    msg.edited = true;
    await msg.save();
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Supprimer un MP
app.post('/delete-pm', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const { messageId } = req.body;
    
    const msg = await PrivateMessage.findById(messageId);
    if (!msg || msg.from !== decoded.username) {
      return res.status(403).json({ error: 'Non autorisé' });
    }
    
    await PrivateMessage.findByIdAndDelete(messageId);
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

io.on('connection', async (socket) => {
  console.log(`✅ ${socket.username} connecté`);
  const user = await User.findOne({ username: socket.username });
  onlineUsers[socket.id] = { username: socket.username, avatar: user?.avatar || null };
  broadcastOnlineUsers();
  broadcastVoiceRooms();

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
      role: user?.role || 'user',
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

// MP en temps réel
socket.on('pm_sent', ({ to, message }) => {
  console.log('🔔 PM envoyé vers:', to);
  
  // Trouver le socket ID du destinataire via onlineUsers
  const recipientSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id].username === to);
  
  console.log('🔍 Socket ID trouvé:', recipientSocketId || 'NON');
  
  if (recipientSocketId) {
    io.to(recipientSocketId).emit('pm_received', message);
    console.log('✅ PM transmis à', to);
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
  console.log(`🚪 ${socket.username} quitte le salon: ${channelId}`);
  console.log(`📊 voiceRooms avant:`, JSON.stringify([...( voiceRooms[channelId] || [])]));
  
  if (voiceRooms[channelId]) {
    voiceRooms[channelId].delete(socket.id);
    voiceRooms[channelId].forEach(peerId => io.to(peerId).emit('peer_left', { peerId: socket.id }));
    if (voiceRooms[channelId].size === 0) delete voiceRooms[channelId];
  }
  
  console.log(`📊 voiceRooms après:`, JSON.stringify([...(voiceRooms[channelId] || [])]));
  broadcastVoiceRooms();
});

  socket.on('signal', ({ to, signal }) => {
    io.to(to).emit('signal', { from: socket.id, signal });
  });
  socket.on('request_voice_rooms_state', () => {
  broadcastVoiceRooms();
});

socket.on('user_streaming', ({ username, streaming }) => {
  io.emit('user_streaming_update', { username, streaming });
});

  socket.on('disconnect', () => {
  console.log(`❌ ${socket.username} déconnecté`);
  
  Object.entries(voiceRooms).forEach(([cId, peers]) => {
    if (peers.has(socket.id)) {
      peers.delete(socket.id);
      peers.forEach(peerId => io.to(peerId).emit('peer_left', { peerId: socket.id }));
    }
    // Nettoyer les salons vides
    if (peers.size === 0) delete voiceRooms[cId];
  });

  delete onlineUsers[socket.id];
  broadcastOnlineUsers();
  broadcastVoiceRooms();
});
  socket.on('ping', () => {
    socket.emit('pong');
  });

  function broadcastOnlineUsers() {
    const users = Object.values(onlineUsers);
    io.emit('online_users', users);
  }

  function broadcastVoiceRooms() {
    const state = {};
    Object.entries(voiceRooms).forEach(([cId, peers]) => {
      peers.forEach(id => {
        if (!onlineUsers[id]) {
          peers.delete(id);
          console.log(`🧹 Peer fantôme supprimé: ${id}`);
        }
      });
      const validPeers = [...peers].map(id => ({
        username: onlineUsers[id]?.username,
        avatar: onlineUsers[id]?.avatar
      })).filter(u => u.username);
      
      if (validPeers.length > 0) state[cId] = validPeers;
    });
    io.emit('voice_rooms_state', state);
  }
});

server.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));