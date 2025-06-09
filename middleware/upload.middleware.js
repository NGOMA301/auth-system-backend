// middleware/upload.middleware.js
import multer, { memoryStorage } from 'multer';
const storage = memoryStorage();
const upload = multer({ storage });

export default upload;
