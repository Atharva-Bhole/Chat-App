import jwt  from "jsonwebtoken";
import User from "../models/user.model.js";
import { StatusCodes } from "http-status-codes";

export const protectRoute = async (req, res, next) => {
    try{
        const token = req.cookies.jwt;

        if(!token)
        {
            return res.status(StatusCodes.FORBIDDEN).json({
                message : "Unauthorized Access"
            })
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY)
        if(!decoded)
        {
            return res.status(StatusCodes.FORBIDDEN).json({
                message : "Unauthorized Access"
            })
        }

        const user = await User.findById(decoded.userId).select("-password");
        if(!user)
        {
            return res.status(StatusCodes.FORBIDDEN).json({
                message : "Unauthorized Access"
            });
        }
        req.user = user;

        next();
    }catch(error)
    {
        console.log(`Internal Server Error : ${error}`);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success : false,
        })
    }
}