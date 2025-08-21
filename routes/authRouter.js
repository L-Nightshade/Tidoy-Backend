// routes/authRouter.js
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.js";

const router = express.Router();

// Register (optional)
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, gender, phone } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "User already exists" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user (include all required fields)
    user = new User({
      name,
      email,
      password: hashedPassword,
      gender,
      phone,
    });

    await user.save();

    res.status(201).json({ message: "User registered successfully", user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check user
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    // Generate token
    console.log("JWT_SECRET is:", process.env.JWT_SECRET);
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "3d",
    });

    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Forgot Password (placeholder)
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    // Add real email sending logic here
    res.json({ message: `Password reset link sent to ${email}` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Logout (optional)
router.post("/logout", (req, res) => {
  res.json({ message: "Logged out" });
});

export default router;
