import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userAgent: String,
  ipAddress: String,
  location: String,
  refreshToken: String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date,
  active: { type: Boolean, default: true },
});

const Session = mongoose.model('Session', sessionSchema);
export default Session;
