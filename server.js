const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'medtrace-dev-secret';

app.use(cors());
app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: true, limit: '3mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const eventSchema = new mongoose.Schema({
  status: { type: String, required: true },
  actorRole: String,
  actorName: String,
  latitude: Number,
  longitude: Number,
  accuracy: Number,
  note: String,
  timestamp: { type: Date, default: Date.now }
}, { _id: false });

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['hospital', 'cbtwf', 'admin'], required: true },
  facilityName: { type: String, default: '' },
  phone: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const wasteSchema = new mongoose.Schema({
  wasteId: { type: String, required: true, unique: true },
  hospitalName: { type: String, required: true },
  hospitalUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  ward: { type: String, required: true },
  wasteType: { type: String, required: true },
  weight: { type: Number, required: true },
  imageData: { type: String, default: '' },
  imageName: { type: String, default: '' },
  gps: { latitude: Number, longitude: Number, accuracy: Number },
  ai: {
    verified: { type: Boolean, default: false },
    mode: { type: String, default: '' },
    detectedCategory: { type: String, default: '' },
    confidence: { type: Number, default: null },
    compartment: { type: String, default: '' },
    verifiedAt: Date
  },
  status: {
    type: String,
    enum: ['REGISTERED', 'AI_VERIFIED', 'PICKUP_REQUESTED', 'COLLECTED', 'IN_TRANSIT', 'RECEIVED', 'TREATMENT_COMPLETED'],
    default: 'REGISTERED'
  },
  pickupRequestedAt: Date,
  treatment: { method: String, operator: String, completedAt: Date },
  events: { type: [eventSchema], default: [] },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const amrSchema = new mongoose.Schema({
  robotId: { type: String, required: true, unique: true },
  apiKey: { type: String, default: '' },
  name: { type: String, default: 'MedTrace AMR' },
  facilityName: { type: String, default: '' },
  status: {
    type: String,
    enum: ['IDLE', 'NAVIGATING', 'COLLECTING', 'RETURNING', 'CHARGING', 'EMERGENCY', 'OFFLINE'],
    default: 'IDLE'
  },
  battery: { type: Number, default: null, min: 0, max: 100 },
  batteryReportedAt: { type: Date, default: null },
  location: {
    ward: { type: String, default: '' },
    latitude: Number,
    longitude: Number,
    accuracy: Number
  },
  destination: { type: String, default: '' },
  lidar: { type: Boolean, default: false },
  camera: { type: Boolean, default: false },
  qrScanner: { type: Boolean, default: false },
  obstacleDetected: { type: Boolean, default: false },
  humanDetected: { type: Boolean, default: false },
  emergencyStop: { type: Boolean, default: false },
  compartments: {
    yellow: { type: Number, default: null, min: 0, max: 100 },
    white: { type: Number, default: null, min: 0, max: 100 },
    red: { type: Number, default: null, min: 0, max: 100 },
    blue: { type: Number, default: null, min: 0, max: 100 }
  },
  telemetryAt: { type: Date, default: null },
  connection: { type: String, enum: ['CONNECTED', 'STALE', 'OFFLINE'], default: 'OFFLINE' },
  pendingCommands: [{ command: String, destination: String, createdAt: { type: Date, default: Date.now } }],
  lastSeen: { type: Date, default: null },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const alertSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['MISSEGREGATION', 'OBSTACLE', 'HUMAN_DETECTED', 'LOW_BATTERY', 'BIN_FILLING', 'BIN_FULL', 'EMERGENCY_STOP', 'NETWORK', 'SYSTEM'],
    required: true
  },
  severity: { type: String, enum: ['INFO', 'WARNING', 'CRITICAL'], default: 'WARNING' },
  message: { type: String, required: true },
  robotId: String,
  wasteId: String,
  data: { type: mongoose.Schema.Types.Mixed, default: null },
  resolved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  resolvedAt: Date
});

const qrScanSchema = new mongoose.Schema({
  wasteId: { type: String, required: true },
  robotId: String,
  scannedAt: { type: Date, default: Date.now },
  latitude: Number,
  longitude: Number,
  accuracy: Number,
  note: String
});

const User = mongoose.model('User', userSchema);
const Waste = mongoose.model('Waste', wasteSchema);
const AMR = mongoose.model('AMR', amrSchema);
const Alert = mongoose.model('Alert', alertSchema);
const QRScan = mongoose.model('QRScan', qrScanSchema);

function tokenFor(user) {
  return jwt.sign(
    { id: user._id.toString(), role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '1d' }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) return res.status(401).json({ message: 'Login required' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Session expired. Login again.' });
  }
}

function allow(...roles) {
  return (req, res, next) =>
    roles.includes(req.user.role)
      ? next()
      : res.status(403).json({ message: 'Access denied' });
}

function makeWasteId() {
  return `MT-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`;
}

function compartment(type) {
  return {
    'Contaminated PPE': 'YELLOW',
    'Sharps': 'WHITE',
    'Plastic Waste': 'RED',
    'Glass Waste': 'BLUE'
  }[type] || 'UNASSIGNED';
}

function pushEvent(waste, status, req, note = '') {
  waste.events.push({
    status,
    actorRole: req.user.role,
    actorName: req.user.name,
    latitude: req.body.latitude,
    longitude: req.body.longitude,
    accuracy: req.body.accuracy,
    note
  });
  waste.status = status;
  waste.updatedAt = new Date();
}

async function ensureDefaultAMR() {}

function telemetryFresh(robot) {
  return Boolean(robot?.telemetryAt && (Date.now() - new Date(robot.telemetryAt).getTime()) <= 30000);
}

function robotConnection(robot) {
  if (!robot?.telemetryAt) return 'OFFLINE';
  const age = Date.now() - new Date(robot.telemetryAt).getTime();
  if (age <= 30000) return 'CONNECTED';
  if (age <= 120000) return 'STALE';
  return 'OFFLINE';
}

function safeNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function validateFill(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = safeNumber(value);
  if (n === null || n < 0 || n > 100) throw new Error('Compartment fill must be between 0 and 100');
  return n;
}

async function createAlert(data) {
  try {
    return await Alert.create(data);
  } catch {
    return null;
  }
}

async function createAlertOnce(data) {
  try {
    const recent = await Alert.findOne({
      type: data.type,
      robotId: data.robotId,
      resolved: false,
      createdAt: { $gte: new Date(Date.now() - 2 * 60 * 1000) }
    });

    if (recent) return recent;
    return await Alert.create(data);
  } catch {
    return null;
  }
}

app.get('/api/health', (req, res) =>
  res.json({ ok: true, service: 'MedTrace API', time: new Date() })
);

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role, facilityName, phone } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({
        message: 'Name, email, password and role are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: 'Password must be at least 6 characters'
      });
    }

    if (!['hospital', 'cbtwf', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const exists = await User.findOne({ email: cleanEmail });

    if (exists) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name: name.trim(),
      email: cleanEmail,
      passwordHash,
      role,
      facilityName: facilityName || '',
      phone: phone || ''
    });

    res.status(201).json({
      token: tokenFor(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        facilityName: user.facilityName,
        phone: user.phone
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    const user = await User.findOne({
      email: (email || '').toLowerCase().trim()
    });

    if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (role && user.role !== role) {
      return res.status(403).json({
        message: `This account is registered as ${user.role}`
      });
    }

    res.json({
      token: tokenFor(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        facilityName: user.facilityName,
        phone: user.phone
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/* =========================
   WASTE MANAGEMENT
   ========================= */

app.post('/api/waste', auth, allow('hospital'), async (req, res) => {
  try {
    const {
      ward,
      wasteType,
      weight,
      imageData,
      imageName,
      latitude,
      longitude,
      accuracy
    } = req.body;

    if (!ward || !wasteType || !weight || !imageData) {
      return res.status(400).json({
        message: 'Ward, waste type, weight and image are required'
      });
    }

    if (Number(weight) <= 0) {
      return res.status(400).json({ message: 'Weight must be greater than 0' });
    }

    if (!String(imageData).startsWith('data:image/')) {
      return res.status(400).json({ message: 'Invalid image data' });
    }

    const user = await User.findById(req.user.id);

    const waste = await Waste.create({
      wasteId: makeWasteId(),
      hospitalName: user.facilityName || user.name,
      hospitalUserId: user._id,
      ward,
      wasteType,
      weight: Number(weight),
      imageData,
      imageName: imageName || '',
      gps: { latitude, longitude, accuracy },
      events: [{
        status: 'REGISTERED',
        actorRole: req.user.role,
        actorName: req.user.name,
        latitude,
        longitude,
        accuracy,
        note: 'Waste bag registered'
      }]
    });

    res.status(201).json(waste);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/waste', auth, async (req, res) => {
  try {
    const filter =
      req.user.role === 'hospital'
        ? { hospitalUserId: req.user.id }
        : {};

    const rows = await Waste.find(filter)
      .sort({ createdAt: -1 })
      .select('-imageData');

    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/waste/:id', async (req, res) => {
  try {
    const waste = await Waste.findOne({ wasteId: req.params.id })
      .select('-imageData');

    if (!waste) {
      return res.status(404).json({ message: 'Waste ID not found' });
    }

    res.json(waste);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/waste/:id/full', auth, async (req, res) => {
  try {
    const waste = await Waste.findOne({ wasteId: req.params.id });

    if (!waste) {
      return res.status(404).json({ message: 'Waste ID not found' });
    }

    if (
      req.user.role === 'hospital' &&
      waste.hospitalUserId.toString() !== req.user.id
    ) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.json(waste);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/waste/:id/verify', auth, allow('hospital'), async (req, res) => {
  try {
    const waste = await Waste.findOne({
      wasteId: req.params.id,
      hospitalUserId: req.user.id
    });

    if (!waste) {
      return res.status(404).json({ message: 'Waste record not found' });
    }

    if (!waste.imageData) {
      return res.status(400).json({
        message: 'Image required before AI verification'
      });
    }

    if (req.body.mode !== 'prototype') {
      return res.status(503).json({
        message: 'YOLO/CNN model is not connected yet. Use Prototype Verification for the hackathon demo.'
      });
    }

    waste.ai = {
      verified: true,
      mode: 'Prototype verification (YOLO/CNN integration-ready)',
      detectedCategory: waste.wasteType,
      confidence: null,
      compartment: compartment(waste.wasteType),
      verifiedAt: new Date()
    };

    waste.status = 'AI_VERIFIED';
    waste.updatedAt = new Date();

    waste.events.push({
      status: 'AI_VERIFIED',
      actorRole: req.user.role,
      actorName: req.user.name,
      latitude: req.body.latitude,
      longitude: req.body.longitude,
      accuracy: req.body.accuracy,
      note: 'Prototype verification completed; replace with YOLO/CNN inference.'
    });

    await waste.save();
    res.json(waste);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/waste/:id/pickup', auth, allow('hospital'), async (req, res) => {
  try {
    const waste = await Waste.findOne({
      wasteId: req.params.id,
      hospitalUserId: req.user.id
    });

    if (!waste) {
      return res.status(404).json({ message: 'Waste record not found' });
    }

    if (!waste.ai.verified || waste.status !== 'AI_VERIFIED') {
      return res.status(400).json({
        message: 'Waste must be AI verified before pickup'
      });
    }

    pushEvent(waste, 'PICKUP_REQUESTED', req, 'Pickup requested by hospital');
    waste.pickupRequestedAt = new Date();

    await waste.save();
    res.json(waste);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

const transitions = {
  COLLECTED: ['PICKUP_REQUESTED'],
  IN_TRANSIT: ['COLLECTED'],
  RECEIVED: ['IN_TRANSIT'],
  TREATMENT_COMPLETED: ['RECEIVED']
};

app.post('/api/waste/:id/status', auth, allow('cbtwf', 'admin'), async (req, res) => {
  try {
    const next = req.body.status;
    const waste = await Waste.findOne({ wasteId: req.params.id });

    if (!waste) {
      return res.status(404).json({ message: 'Waste record not found' });
    }

    if (!transitions[next]) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    if (!transitions[next].includes(waste.status)) {
      return res.status(400).json({
        message: `Cannot move from ${waste.status} to ${next}`
      });
    }

    pushEvent(waste, next, req, `Status updated to ${next}`);

    if (next === 'TREATMENT_COMPLETED') {
      waste.treatment = {
        method: req.body.method || '',
        operator: req.user.name,
        completedAt: new Date()
      };
    }

    await waste.save();
    res.json(waste);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/waste/:id/timeline', async (req, res) => {
  try {
    const waste = await Waste.findOne({ wasteId: req.params.id }).select(
      'wasteId hospitalName ward wasteType weight status ai gps events createdAt updatedAt'
    );

    if (!waste) {
      return res.status(404).json({ message: 'Waste ID not found' });
    }

    res.json({
      wasteId: waste.wasteId,
      hospitalName: waste.hospitalName,
      ward: waste.ward,
      wasteType: waste.wasteType,
      weight: waste.weight,
      currentStatus: waste.status,
      ai: waste.ai,
      origin: waste.gps,
      events: waste.events,
      createdAt: waste.createdAt,
      updatedAt: waste.updatedAt
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/* =========================
   QR TRACEABILITY
   ========================= */

app.post('/api/waste/:id/qr-scan', auth, async (req, res) => {
  try {
    const waste = await Waste.findOne({ wasteId: req.params.id });

    if (!waste) {
      return res.status(404).json({ message: 'Waste ID not found' });
    }

    const scan = await QRScan.create({
      wasteId: waste.wasteId,
      robotId: req.body.robotId || '',
      latitude: req.body.latitude,
      longitude: req.body.longitude,
      accuracy: req.body.accuracy,
      note: req.body.note || 'QR code scanned'
    });

    waste.events.push({
      status: waste.status,
      actorRole: req.user.role,
      actorName: req.user.name,
      latitude: req.body.latitude,
      longitude: req.body.longitude,
      accuracy: req.body.accuracy,
      note: `QR scan recorded${req.body.robotId ? ` by ${req.body.robotId}` : ''}`
    });

    if (waste.status === 'PICKUP_REQUESTED' && req.body.autoCollect !== false) {
      waste.status = 'COLLECTED';
      waste.events.push({
        status: 'COLLECTED',
        actorRole: req.user.role,
        actorName: req.user.name,
        latitude: req.body.latitude,
        longitude: req.body.longitude,
        accuracy: req.body.accuracy,
        note: 'AMR/collector QR scan confirmed pickup'
      });
    }

    waste.updatedAt = new Date();
    await waste.save();

    res.status(201).json({
      message: 'QR scan recorded',
      scan,
      waste
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/* =========================
   AMR MANAGEMENT
   ========================= */

app.get('/api/amr', auth, async (req, res) => {
  try {
    const filter = req.user.role === 'hospital'
      ? { facilityName: (await User.findById(req.user.id).select('facilityName'))?.facilityName || '' }
      : {};
    const robots = await AMR.find(filter).sort({ robotId: 1 });
    for (const robot of robots) {
      const previous = robot.connection;
      const current = robotConnection(robot);
      robot.connection = current;
      if (current === 'OFFLINE' && robot.status !== 'OFFLINE') robot.status = 'OFFLINE';
      await robot.save();
      if (previous && previous !== current && current !== 'CONNECTED') {
        await createAlertOnce({
          type: 'NETWORK',
          severity: current === 'OFFLINE' ? 'CRITICAL' : 'WARNING',
          message: `${robot.name} telemetry connection is ${current.toLowerCase()}`,
          robotId: robot.robotId,
          data: { previous, current }
        });
      }
    }
    const visible = await AMR.find(filter).sort({ robotId: 1 });
    res.json(visible.map(r => { const x = r.toObject(); delete x.apiKey; return x; }));
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/amr/:robotId', auth, async (req, res) => {
  try {
    const robot = await AMR.findOne({ robotId: req.params.robotId });

    if (!robot) {
      return res.status(404).json({ message: 'AMR not found' });
    }
    if (req.user.role === 'hospital') {
      const user = await User.findById(req.user.id).select('facilityName');
      if (!user || user.facilityName !== robot.facilityName) return res.status(403).json({ message: 'AMR belongs to another facility' });
    }

    robot.connection = robotConnection(robot);
    if (robot.connection === 'OFFLINE' && robot.status !== 'OFFLINE') robot.status = 'OFFLINE';
    await robot.save();
    const data = robot.toObject(); delete data.apiKey;
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/amr/register', auth, allow('admin'), async (req, res) => {
  try {
    const robotId = String(req.body.robotId || '').trim();
    const facilityName = String(req.body.facilityName || '').trim();
    if (!robotId) return res.status(400).json({ message: 'Robot ID is required' });
    if (!facilityName) return res.status(400).json({ message: 'Facility name is required' });
    if (await AMR.findOne({ robotId })) return res.status(409).json({ message: 'Robot ID already exists' });

    const apiKey = require('crypto').randomBytes(24).toString('hex');
    let robot = await AMR.findOne({ robotId });
    if (robot) {
      if (robot.apiKey) return res.status(409).json({ message: 'Robot ID already exists and is already connected to a controller. Use a new Robot ID.' });
      robot.name = req.body.name || robot.name || `MedTrace ${robotId}`;
      robot.facilityName = facilityName;
      robot.apiKey = apiKey;
      robot.status = 'OFFLINE';
      robot.battery = null;
      robot.batteryReportedAt = null;
      robot.telemetryAt = null;
      robot.connection = 'OFFLINE';
      await robot.save();
    } else {
      robot = await AMR.create({
        robotId,
        name: req.body.name || `MedTrace ${robotId}`,
        facilityName,
        status: 'OFFLINE',
        battery: null,
        lidar: false,
        camera: false,
        qrScanner: false,
        connection: 'OFFLINE',
        apiKey
      });
    }

    const safeRobot = robot.toObject();
    delete safeRobot.apiKey;
    res.status(201).json({
      robot: safeRobot,
      apiKey,
      message: 'AMR registered. Store this API key on the robot controller; it will not be shown again.'
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

async function robotAuth(req, res, next) {
  const key = req.headers['x-amr-key'];
  if (!key) return res.status(401).json({ message: 'AMR API key required' });
  const robot = await AMR.findOne({ robotId: req.params.robotId });
  if (!robot || !robot.apiKey || robot.apiKey !== key) return res.status(401).json({ message: 'Invalid AMR API key' });
  req.robot = robot;
  next();
}

app.post('/api/amr/:robotId/telemetry', robotAuth, async (req, res) => {
  try {
    const robot = req.robot;
    const {
      status, battery, ward, latitude, longitude, accuracy, destination,
      lidar, camera, qrScanner, obstacleDetected, humanDetected, emergencyStop,
      fillLevels, binFull
    } = req.body;

    if (status) robot.status = status;
    if (battery !== undefined) {
      const b = safeNumber(battery);
      if (b === null || b < 0 || b > 100) return res.status(400).json({ message: 'Battery must be 0-100' });
      robot.battery = b;
      robot.batteryReportedAt = new Date();
    }
    if (ward !== undefined) robot.location.ward = ward;
    if (latitude !== undefined) robot.location.latitude = safeNumber(latitude);
    if (longitude !== undefined) robot.location.longitude = safeNumber(longitude);
    if (accuracy !== undefined) robot.location.accuracy = safeNumber(accuracy);
    if (destination !== undefined) robot.destination = destination;
    if (lidar !== undefined) robot.lidar = Boolean(lidar);
    if (camera !== undefined) robot.camera = Boolean(camera);
    if (qrScanner !== undefined) robot.qrScanner = Boolean(qrScanner);
    if (obstacleDetected !== undefined) robot.obstacleDetected = Boolean(obstacleDetected);
    if (humanDetected !== undefined) robot.humanDetected = Boolean(humanDetected);
    if (emergencyStop !== undefined) robot.emergencyStop = Boolean(emergencyStop);

    if (fillLevels) {
      for (const key of ['yellow', 'white', 'red', 'blue']) {
        if (fillLevels[key] !== undefined) robot.compartments[key] = validateFill(fillLevels[key]);
      }
    }

    if (binFull) {
      for (const key of ['yellow', 'white', 'red', 'blue']) {
        if (binFull[key] !== undefined) robot.compartments[key] = binFull[key] ? 100 : (robot.compartments[key] ?? 0);
      }
    }

    robot.telemetryAt = new Date();
    robot.lastSeen = robot.telemetryAt;
    robot.connection = 'CONNECTED';
    robot.updatedAt = new Date();
    await robot.save();

    const createFillAlert = async (color, level) => {
      if (level === null || level === undefined) return;
      if (level >= 95) {
        await createAlertOnce({
          type: 'BIN_FULL', severity: 'CRITICAL',
          message: `${robot.name} ${color.toUpperCase()} compartment is full (${level}%)`,
          robotId: robot.robotId, data: { compartment: color, fill: level }
        });
      } else if (level >= 80) {
        await createAlertOnce({
          type: 'BIN_FILLING', severity: 'WARNING',
          message: `${robot.name} ${color.toUpperCase()} compartment is ${level}% full`,
          robotId: robot.robotId, data: { compartment: color, fill: level }
        });
      }
    };

    if (robot.battery !== null && robot.battery <= 20) {
      await createAlertOnce({
        type: 'LOW_BATTERY',
        severity: robot.battery <= 10 ? 'CRITICAL' : 'WARNING',
        message: `${robot.name} battery is ${robot.battery}%`,
        robotId: robot.robotId,
        data: { battery: robot.battery }
      });
    }

    for (const color of ['yellow', 'white', 'red', 'blue']) {
      await createFillAlert(color, robot.compartments[color]);
    }

    if (robot.obstacleDetected) await createAlertOnce({ type: 'OBSTACLE', severity: 'WARNING', message: `Obstacle detected by ${robot.name}`, robotId: robot.robotId });
    if (robot.humanDetected) await createAlertOnce({ type: 'HUMAN_DETECTED', severity: 'INFO', message: `Human detected near ${robot.name}; navigation safety check triggered`, robotId: robot.robotId });
    if (robot.emergencyStop) await createAlertOnce({ type: 'EMERGENCY_STOP', severity: 'CRITICAL', message: `Emergency stop activated on ${robot.name}`, robotId: robot.robotId });

    res.json({ message: 'Telemetry accepted', robot });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/amr/:robotId/telemetry', auth, async (req, res) => {
  try {
    const robot = await AMR.findOne({ robotId: req.params.robotId });
    if (!robot) return res.status(404).json({ message: 'AMR not found' });
    robot.connection = robotConnection(robot);
    await robot.save();
    res.json(robot);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/amr/:robotId/command', auth, allow('hospital', 'admin', 'cbtwf'), async (req, res) => {
  try {
    const robot = await AMR.findOne({ robotId: req.params.robotId });
    if (!robot) return res.status(404).json({ message: 'AMR not found' });
    if (req.user.role === 'hospital') {
      const user = await User.findById(req.user.id).select('facilityName');
      if (!user || user.facilityName !== robot.facilityName) return res.status(403).json({ message: 'AMR belongs to another facility' });
    }

    const commands = ['START', 'COLLECT', 'RETURN', 'CHARGE', 'STOP', 'EMERGENCY_STOP'];
    const { command, destination = '' } = req.body;
    if (!commands.includes(command)) return res.status(400).json({ message: 'Invalid AMR command' });

    robot.pendingCommands.push({ command, destination });
    await robot.save();

    await createAlert({
      type: 'SYSTEM',
      severity: 'INFO',
      message: `${command} command queued for ${robot.name}`,
      robotId: robot.robotId,
      data: { command, destination, requestedBy: req.user.name }
    });

    res.json({ message: `${command} command queued for the AMR controller`, robotId: robot.robotId });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/amr/:robotId/commands', robotAuth, async (req, res) => {
  try {
    res.json({ commands: req.robot.pendingCommands || [] });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/amr/:robotId/commands/:commandId/ack', robotAuth, async (req, res) => {
  try {
    const command = req.robot.pendingCommands.id(req.params.commandId);
    if (!command) return res.status(404).json({ message: 'Command not found' });
    req.robot.pendingCommands.pull(command._id);
    if (req.body.status) req.robot.status = req.body.status;
    if (req.body.destination !== undefined) req.robot.destination = req.body.destination;
    req.robot.telemetryAt = new Date();
    req.robot.lastSeen = req.robot.telemetryAt;
    req.robot.connection = 'CONNECTED';
    await req.robot.save();
    res.json({ message: 'Command acknowledged' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/* =========================
   ALERTS
   ========================= */

app.get('/api/alerts', auth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const filter =
      req.query.resolved === 'true'
        ? { resolved: true }
        : req.query.resolved === 'false'
          ? { resolved: false }
          : {};

    res.json(
      await Alert.find(filter)
        .sort({ createdAt: -1 })
        .limit(limit)
    );
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/alerts/:id/resolve', auth, allow('hospital', 'admin'), async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    alert.resolved = true;
    alert.resolvedAt = new Date();

    await alert.save();
    res.json(alert);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/* =========================
   DASHBOARDS / REPORTS
   ========================= */

app.get('/api/dashboard/summary', auth, async (req, res) => {
  try {
    const filter =
      req.user.role === 'hospital'
        ? { hospitalUserId: req.user.id }
        : {};

    const [
      total,
      verified,
      inTransit,
      completed,
      weightAgg,
      byType,
      activeAlerts,
      activeRobots
    ] = await Promise.all([
      Waste.countDocuments(filter),
      Waste.countDocuments({ ...filter, 'ai.verified': true }),
      Waste.countDocuments({ ...filter, status: 'IN_TRANSIT' }),
      Waste.countDocuments({ ...filter, status: 'TREATMENT_COMPLETED' }),
      Waste.aggregate([
        { $match: filter },
        { $group: { _id: null, totalWeight: { $sum: '$weight' } } }
      ]),
      Waste.aggregate([
        { $match: filter },
        { $group: { _id: '$wasteType', count: { $sum: 1 }, weight: { $sum: '$weight' } } },
        { $sort: { count: -1 } }
      ]),
      Alert.countDocuments({ resolved: false }),
      AMR.countDocuments({ connection: 'CONNECTED' })
    ]);

    res.json({
      total,
      verified,
      inTransit,
      completed,
      totalWeight: weightAgg[0]?.totalWeight || 0,
      activeAlerts,
      activeRobots,
      byType
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/reports/waste', auth, async (req, res) => {
  try {
    const filter =
      req.user.role === 'hospital'
        ? { hospitalUserId: req.user.id }
        : {};

    const rows = await Waste.find(filter)
      .select('-imageData')
      .sort({ createdAt: -1 })
      .limit(Math.min(Number(req.query.limit) || 200, 1000));

    res.json({
      generatedAt: new Date(),
      count: rows.length,
      rows
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/system/status', auth, async (req, res) => {
  try {
    const robots = await AMR.find().sort({ robotId: 1 });
    for (const robot of robots) {
      robot.connection = robotConnection(robot);
      if (robot.connection === 'OFFLINE' && robot.status !== 'OFFLINE') robot.status = 'OFFLINE';
      await robot.save();
    }
    const unresolvedAlerts = await Alert.countDocuments({ resolved: false });
    res.json({
      api: 'ONLINE',
      database: mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED',
      connectedRobots: robots.filter(r => r.connection === 'CONNECTED').length,
      totalRobots: robots.length,
      unresolvedAlerts
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/admin/stats', auth, allow('admin'), async (req, res) => {
  try {
    const [total, verified, pickup, inTransit, completed] = await Promise.all([
      Waste.countDocuments(),
      Waste.countDocuments({ 'ai.verified': true }),
      Waste.countDocuments({ status: 'PICKUP_REQUESTED' }),
      Waste.countDocuments({ status: 'IN_TRANSIT' }),
      Waste.countDocuments({ status: 'TREATMENT_COMPLETED' })
    ]);

    const byType = await Waste.aggregate([
      { $group: { _id: '$wasteType', count: { $sum: 1 }, weight: { $sum: '$weight' } } },
      { $sort: { count: -1 } }
    ]);

    res.json({ total, verified, pickup, inTransit, completed, byType });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/admin/users', auth, allow('admin'), async (req, res) => {
  try {
    res.json(
      await User.find()
        .select('-passwordHash')
        .sort({ createdAt: -1 })
    );
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!process.env.MONGO_URI) {
  console.error('MONGO_URI is missing. Create a .env file beside server.js and set MONGO_URI.');
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected');
    await ensureDefaultAMR();
    app.listen(PORT, () => {
      console.log(`MedTrace API running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  });
