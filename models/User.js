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
  email: {
    type: String,
    required: function() { return this.role === 'teacher'; },
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address'],
    unique: function() { return this.role === 'teacher'; }
  },
  password: {
    type: String,
    required: [true, 'Password is required']
  },
  role: {
    type: String,
    required: [true, 'Role is required'],
    enum: ['student', 'admin', 'teacher']
  },
  subject: {
    type: String,
    required: function() { return this.role === 'teacher'; }
  },
  course: {
    type: String,
    required: function() { return this.role === 'student'; },
    enum: ['ict', 'nursing', 'clinical medicine']
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Add indexes
UserSchema.index({ identity: 1 }, { unique: true, partialFilterExpression: { isDeleted: false } });
UserSchema.index({ email: 1 }, { 
  unique: true, 
  partialFilterExpression: { 
    role: 'teacher',
    isDeleted: false 
  },
  sparse: true
});

// Middleware to handle queries
UserSchema.pre('find', function() {
  this.where({ isDeleted: false });
});

UserSchema.pre('findOne', function() {
  this.where({ isDeleted: false });
});

const User = mongoose.model('User', UserSchema);

module.exports = User;