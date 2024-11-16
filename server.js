import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { rateLimit } from 'express-rate-limit';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

// Set strictQuery to suppress deprecation warning
mongoose.set('strictQuery', true);

// Update CORS configuration
app.use(cors({
  origin: 'http://localhost:3000',  // Replace with your frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow specific methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow specific headers
  credentials: true, // Allow cookies to be sent across origins
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Improved MongoDB connection function
const connectDB = async () => {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined in the environment variables');
    }
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

connectDB();

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const complaintSchema = new mongoose.Schema({
  subject: { type: String, required: true, trim: true },
  description: { type: String, required: true, trim: true },
  status: {
    type: String,
    enum: ['Pending', 'In Progress', 'Resolved'],
    default: 'Pending'
  },
  createdAt: { type: Date, default: Date.now },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
});

const Complaint = mongoose.model('Complaint', complaintSchema);

const verifyToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ message: 'Invalid token' });
  }
};

app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    if (user && (await bcrypt.compare (password, user.password))) {
      const accessToken = jwt.sign({
          user: {
              name: user.name, 
              email: user.email, 
              id: user.id,
          },
   },
      process.env.JWT_SECRET,
      { expiresIn: 86000 }
   )
      res.status(200).json({accessToken})
   } else {
      res.status(401)
      res.json("Email or Password is not Valid")
      throw new Error("email or password is not valid")
   }  
});



app.get('/api/complaints', verifyToken, async (req, res) => {

  try {
    const comp = await Complaint.find()
    res.status(200).json(comp)
  }
  catch (e) {
    throw new Error ("Fetching Error")
  }
})
app.post('/api/complaints', verifyToken, async (req, res) => {
  try {
    const { subject, description } = req.body;
    
    if (!subject || !description) {
      return res.status(400).json({ message: 'Subject and description are required' });
    }

    console.log(req.user.user.id);
    

    const newComplaint = new Complaint({
      subject,
      description,
      user: req.user.user.id
    });
    
    await newComplaint.save();
    res.status(201).json(newComplaint);
  } catch (error) {
    res.status(500).json({ message: 'Error creating complaint', error: error.message });
  }
});

app.get('/', (req, res) => {
    res.send('Hello, World!');
  });
  

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});