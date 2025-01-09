import Message from "../models/message.model.js";
import { StatusCodes } from "http-status-codes";
import User from "../models/user.model.js";
import cloudinary from "../lib/cloudinary.js";
export const getUserForSidebar = async (req, res) => {
    try{
        const loggedInUser = req.user._id;
        const filteredUser = await User.find({_id : {$ne : loggedInUser}}).select("-password");
        res.status(StatusCodes.OK).json(filteredUser);
    }catch(error)
    {
        console.log(error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
            message : "INTERNAL SERVER ERROR"
        })
    }
}

export const getMessages = async (req, res) => {
    try{
        const {id : userToChatId} = req.params;
        const myId = req.user._id; 

        const messages = await Message.find({
            $or:[
                {senderId : myId, receiverId : userToChatId},
                {senderId : userToChatId, receiverId : myId}
            ]
        });

        res.status(StatusCodes.OK).json({
            success : true,
            messages,
        });
    }catch(error)
    {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
            messsage : "Internal Server Error",
        });
    }
}

export const sendMessage = async (req, res) => {
    try{
        const {text, image} = req.body;
        const sender = req.user._id;
        const receiverId = req.params.id;
        let imageUrl;
        if(image)
        {
            const uploadResponse = await cloudinary.uploader.upload(image);
            imageUrl = uploadResponse.secure_url;
        }
        const newMessage = Message.create({
            senderId : sender,
            receiverId : receiverId,
            text : text,
            image : imageUrl
        });

        await newMessage.save();

        // realtime chat functionality insert here

        // end functionality

        res.status(StatusCodes.CREATED).json({
            newMessage
        })
    }catch(error)
    {
        console.log("Error sending message", error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
            message : "Error Sending Message, INTERNAL SERVER ERROR"     
        })
    }
}