import User from "../models/user.model.js";
import StatusCodes from "http-status-codes";
import bcrypt from "bcryptjs";
import { generateToken } from "../lib/utils.js";
import cloudinary from "../lib/cloudinary.js";

export const signup = async (req, res)=>{
    try{
        const {name, email, password} = req.body;
        if(password.length < 6)
        {
            return res.status(StatusCodes.BAD_REQUEST).json({
                success : false,
                message : "Password length should be more than 6"
            });
        }
        const user =  await User.findOne({email});
        if(user)
        {
            res.status(StatusCodes.BAD_REQUEST).json({
                success : false,
                message : "User already exists in Database"
            });
        }
        else{
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const newUser = await User.create({
                name,
                email,
                password : hashedPassword
            });

            if(newUser)
            {
                // generate jwt here
                generateToken(newUser._id, res)
                await newUser.save();

                res.status(StatusCodes.OK).json({
                    _id : newUser._id,
                    name : newUser.name,
                    email : newUser.email,
                    profilePic : newUser.profilePic
                });

            }
        }
    }catch(error){
        console.log(`Error creating user : ${error}`);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
            error
        })
    }
}

export const login = async(req, res)=>{
    try{
        const {email, password} = req.body;
        const user = await User.findOne({email});

        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        
        if(!isPasswordCorrect){
            res.status(StatusCodes.FORBIDDEN).json({
                success : false,
                message : "Invalid Credentials",
            });
        }

        generateToken(user._id, res);
        res.status(StatusCodes.OK).json({
            success : true,
            message : "Login Successful",
            user
        });
        
        
    }catch(error)
    {
        console.log(`Error Loggin In ${error}`);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
            message : error
        });
    }

}

export const logout = (req, res)=>{
    try{
        res.cookie("jwt", "", {maxAge : 0})
        res.status(StatusCodes.OK).json({
            message : "Log Out successful"
        });
    }catch(error)
    {
        console.log(`Internal Server Error ${error}`);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
            message : "Internal Server Error"
        });
    }
}


export const updateProfile = async (req, res)=>{
    try{
        const {profilePic} = req.body;
        const userId = req.user._id;
        if(!profilePic)
        {
            res.status(StatusCodes.BAD_REQUEST).json({ message : "Profile pic is required" });
        }

        const uploadResponse = await cloudinary.uploader.upload(profilePic);
        const updatedUser = await User.findByIdAndUpdate(userId, {profilePic : uploadResponse.secure_url}, {new : true});
        res.status(StatusCodes.OK).json({updatedUser});
    }catch(error)
    {
        console.log(`Error ${error}`);
        
    }
}