const express= require('express');
const router= express.Router();
const bcrypt=require('bcryptjs');
const config=require('config')
const jwt=require('jsonwebtoken');
const User=require('../models/User');
const {check,validationResult}=require('express-validator');
const auth=require('../middleware/auth')

//@route  GET api/auth
//@desc   Get logged in user
//@access Private

router.get('/',auth, async (req,res)=>{
    try {
        const user=await User.findById(req.user.id).select('-password');
        res.json(user)
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error')
        
    }
});


//@route  POST api/auth
//@desc   Auth user and get token
//@access Public

router.post('/',
[
    check('email','Please enter a valid email').isEmail(),
    check('password','Please enter a valid password').exists()
], async (req,res)=>{
    const errors=validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors:errors.array()});
}
const {email, password}=req.body;


try {
    let user=await User.findOne({email})
    if(!user){
        res.status(400).json({msg:'Invalid Credentials'})
    }
    
    const isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch){
        res.status(400).json({msg:'Invalid Credentials'})
    }
    
    
    
    const payload={
        user:{
            id:user.id
        }
    };
    console.log(config.get('jwtSecret'))
    jwt.sign(payload,config.get('jwtSecret'),{expiresIn:'2d'},(err,token)=>{
        if(err) throw err;
        res.json({token})
    });
    

} catch (err) {
    console.error(err.msg)
    res.status(500).send('Server Error')
}
}
);
module.exports=router;