 const mongoose = require("mongoose");
 const {Schema} = mongoose;

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
   }
}, { timestamps: true });



const UserModel = mongoose.model('User', UserSchema);

 module.exports = UserModel;