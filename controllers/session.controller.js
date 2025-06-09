import Session from '../models/session.model.js';

export const getSessions = async (req, res) => {
  try {
    const sessions = await Session.find({ user: req.userId, active: true })
      .sort({ createdAt: -1 })
      .select('-refreshToken');

    res.status(200).json(sessions);
  } catch (err) {
    console.error('Get sessions error:', err);
    res.status(500).json({ message: 'Failed to fetch sessions' });
  }
};

export const logoutSession = async (req, res) => {
  try {
    const session = await Session.findOne({
      _id: req.params.sessionId,
      user: req.userId,
    });

    if (!session)
      return res.status(404).json({ message: 'Session not found' });

    session.active = false;
    await session.save();

    res.status(200).json({ message: 'Session terminated successfully' });
  } catch (err) {
    console.error('Logout session error:', err);
    res.status(500).json({ message: 'Failed to terminate session' });
  }
};
