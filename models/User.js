
const mongoose = require("mongoose");
const { Schema } = mongoose;

const UserSchema = new Schema({
  name: {
    type: String,
    required: [true, 'Name is required']
  },
  identity: {
    type: String,
    required: [true, 'Student No/Employee No is required'],
    unique: true,
  },
  password: {
    type: String,
    required: [true, 'Password is required']
  },
  role: {
    type: String,
    required: [true, 'Role is required'],
    enum: ['student', 'admin']
  },
  course: {
    type: String,
    required: function() { return this.role === 'student'; },
    enum: ['ict', 'nursing', 'clinical medicine']
  }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
module.exports = User;