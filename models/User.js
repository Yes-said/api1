const mongoose = require("mongoose");
const {Schema} = mongoose;

const UserSchema = new Schema({
name: String,
admission: {type:String, unique:true},
email: {type:String,unique:true},
password: String,
role: { type: String, enum: ['student', 'admin'], required: true }, 
});


const UserModel = mongoose.model("User", UserSchema);

module.exports = UserModel;