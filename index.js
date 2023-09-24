// server.js

const express = require('express')
const mongoose = require('mongoose')
const dotenv = require('dotenv')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// Middleware for JSON parsing and CORS
app.use(express.json())
app.use(cors())

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB')
})

// User Model
const User = mongoose.model('User', {
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
})

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET

// Routes
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body
    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({ username, password: hashedPassword })
    await user.save()
    res.status(201).json({ message: 'User created successfully' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await User.findOne({ username })

    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' })
    }

    const passwordMatch = await bcrypt.compare(password, user.password)
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Authentication failed' })
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: '1h'
    })

    res.status(200).json({ token })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Internal server error' })
  }
})

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
