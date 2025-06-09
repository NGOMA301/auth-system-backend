import { Router } from 'express';
import { getSessions, logoutSession } from '../controllers/session.controller.js';
import { verifyToken } from '../middleware/auth.middleware.js';

const router = Router();

router.get('/', verifyToken, getSessions);
router.delete('/:sessionId', verifyToken, logoutSession);

export default router;
