// models/user.model.js
import { Schema, model } from 'mongoose';

const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profileImageUrl: String,
}, { timestamps: true });

export default model('User', userSchema);
