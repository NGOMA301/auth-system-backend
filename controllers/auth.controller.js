import crypto from 'crypto';
import Session from '../models/session.model.js';
import useragent from 'express-useragent';
import geoip from 'geoip-lite';


import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';
import { uploadToS3 } from '../utils/s3.js';

const JWT_EXPIRES_IN = '15m';
const REFRESH_EXPIRES_IN = '3d';

const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_EXPIRES_IN }
  );

  return { accessToken, refreshToken };
};

const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};


export const register = async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!req.file) return res.status(400).json({ message: 'Profile picture is required' });

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ message: 'Email or username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const s3Result = await uploadToS3(req.file);

    const newUser = await User.create({
      email,
      username,
      password: hashedPassword,
      profileImageUrl: s3Result.Location,
    });

    const tokens = generateTokens(newUser);

    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser._id,
        email: newUser.email,
        username: newUser.username,
        profileImageUrl: newUser.profileImageUrl,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

export const login = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const tokens = generateTokens(user);
    const hashedRefresh = hashToken(tokens.refreshToken);

    const userAgent = req.headers['user-agent'];
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const location = geoip.lookup(ip)?.city || 'Unknown';

    await Session.create({
      user: user._id,
      userAgent,
      ipAddress: ip,
      location,
      refreshToken: hashedRefresh,
      expiresAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
    });

    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    res.status(200).json({
      message: 'Logged in successfully',
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        profileImageUrl: user.profileImageUrl,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};



export const refreshToken = async (req, res) => {
  const refresh = req.cookies.refreshToken;
  if (!refresh) return res.status(401).json({ message: 'No refresh token' });

  try {
    const decoded = jwt.verify(refresh, process.env.JWT_REFRESH_SECRET);
    const hashed = hashToken(refresh);

    const session = await Session.findOne({
      user: decoded.id,
      refreshToken: hashed,
      active: true,
    });

    if (!session || session.expiresAt < Date.now()) {
      return res.status(403).json({ message: 'Invalid session' });
    }

    const newAccessToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    res.status(200).json({ message: 'Token refreshed' });
  } catch (err) {
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};

export const logout = async (req, res) => {
  try {
    const refresh = req.cookies.refreshToken;
    if (refresh) {
      const decoded = jwt.verify(refresh, process.env.JWT_REFRESH_SECRET);
      const hashed = hashToken(refresh);

      // Find and deactivate the session
      await Session.findOneAndUpdate(
        { user: decoded.id, refreshToken: hashed },
        { active: false }
      );
    }
  } catch (err) {
    // Even if token is invalid, proceed with cookie clearing
  }

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  res.status(200).json({ message: 'Logged out successfully' });
};


export const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};