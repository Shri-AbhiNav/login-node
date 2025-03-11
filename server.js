require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

// Initialize Firebase Admin SDK
const serviceAccount = require("./serviceAccountKey.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Define User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  phoneNumber: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);

// 📌 API to Register User & Send OTP via Firebase
app.post("/register", async (req, res) => {
  try {
    const { name, phoneNumber, password } = req.body;

    if (!name || !phoneNumber || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ phoneNumber });
    if (existingUser) {
      return res.status(400).json({ message: "User already registered" });
    }

    // Send OTP using Firebase (Handled on the frontend)
    res.json({ message: "OTP sent successfully. Verify OTP using /verify-otp." });

  } catch (error) {
    res.status(500).json({ message: "Error sending OTP", error: error.message });
  }
});

// 📌 API to Verify OTP and Register User
app.post("/verify-otp", async (req, res) => {
  try {
    const { idToken, name, phoneNumber, password } = req.body;

    if (!idToken || !name || !phoneNumber || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Verify OTP using Firebase Admin SDK
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const verifiedPhoneNumber = decodedToken.phone_number;

    if (!verifiedPhoneNumber || verifiedPhoneNumber !== phoneNumber) {
      return res.status(400).json({ message: "OTP verification failed" });
    }

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to MongoDB
    const newUser = new User({
      name,
      phoneNumber,
      password: hashedPassword,
    });

    await newUser.save();

    res.json({ message: "User registered successfully", userId: newUser._id });

  } catch (error) {
    res.status(500).json({ message: "Error verifying OTP", error: error.message });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
