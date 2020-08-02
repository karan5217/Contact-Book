const express= require('express');
const router= express.Router();
const bcrypt=require('bcryptjs');
const config=require('config')
const jwt=require('jsonwebtoken')
const User=require('../models/User');


const {check,validationResult}=require('express-validator');
//@route  POST api/users
//@desc   Register a user
//@access Public


router.post('/',[
    check('name','name is required')
    .not()
    .isEmpty(),
    check('email','Please Enter a valid email').isEmail(),
    check('password','Please enter the password with 6 characters').isLength({min:6})
], async (req,res)=>{
    const errors=validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors:errors.array()});
    }
    const { name, password, email}=req.body;
    try {

        let user = await User.findOne({email})
        console.log(user)
        if (user){
            return res.status(400).json({msg:'user already exists'});
        }

        user=new User({
            name,
            email,
            password
        });

        const salt= await bcrypt.genSalt(10);
        user.password=await bcrypt.hash(password,salt);
        await user.save();
        const payload={
            user:{
                id:user.id
            }
        };
        console.log(config.get('jwtSecret'))
        jwt.sign(payload,config.get('jwtSecret'),{expiresIn:"2d"},(err,token)=>{
            if (err) throw err;
            res.json({token});
        });
    } catch (error) {

        console.error(error.message);
        res.status(500).send('Server Error')
        
    }
});

module.exports = router;