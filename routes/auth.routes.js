// routes/auth.routes.js
import express from 'express';
import upload from '../middleware/upload.middleware.js';
import {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
} from '../controllers/auth.controller.js';
import { verifyToken } from '../middleware/auth.middleware.js';

const router = express.Router();

router.post('/register', upload.single('profile'), register);
router.post('/login', login);
router.get('/refresh-token', refreshToken);
router.get('/logout', logout);
router.get('/me', verifyToken, getProfile);

export default router;
