import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";


const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = await user.generateAccessToken();
    const refreshToken = await user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh & access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  // validation - not empty
  // check if user already exists: username, email
  // check for images, check for avatar
  // upload them to cloudinary, avatar
  // create user object - create entry in db
  // remove password and refresh token field from response
  // check for user creation
  // return res

  const { fullname, email, password, username } = req.body;
  //console.log("email:", email)

  if (
    [fullname, email, password, username].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // check if user already exists: username, email
  const existedUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existedUser) {
    throw new ApiError(409, "User already exists");
  }

  // check for images, check for avatar
  // upload them to cloudinary, avatar
  const avatarLocalPath = req?.files?.avatar[0]?.path;
  //const coverImageLocalPath = req?.files?.coverImage[0]?.path;

  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // create user object - create entry in db

  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  // remove password and refresh token field from response
  // check for user creation
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering user");
  }

  // return res
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, " User successfully registered"));
});

// Middleware to handle login endpoint
const loginUser = asyncHandler(async (req, res) => {
  // Destructure email, username, and password from request body
  const { email, username, password } = req.body;
  console.log(email)

  // Check if username and email are provided
  if (!username && !email) {
    // Throw an error if not
    throw new ApiError(400, "Username and email are required");
  }

  // Find user by email or username
  const user = await User.findOne({
    $or: [{ email }, { username }],
  });

  // If user is not found
  if (!user) {
    // Throw an error
    throw new ApiError(400, "User doesn't exist");
  }

  // Check if password is correct
  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    // Throw an error if password is incorrect
    throw new ApiError(401, "Invalid password");
  }

  // Generate access and refresh tokens
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  // Find user again to exclude password and refreshToken
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

  // Set options for cookies
  const options = {
    httpOnly: true,
    secure: true,
  };

  // Return response with user, accessToken, refreshToken, and success message
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User successfully logged in"
      )
    );
});

const logoutUser = asyncHandler(async(req, res)=>{
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1,
      },
    },
  { new: true }
  )
  const options = {
    httpOnly: true,
    secure: true,
  }
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "user loged out"))
})

const  refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = res.cookies.refreshToken || req.body.refreshToken
  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized request")
  }
  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    )
  
    const user = await User.findById(decodedToken?._id)
  
    if(!user){
      throw new ApiError(401, "Invalid Refresh Token")
    }
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh Token expired")
    }
  
    const options ={
      httpOnly: true,
      secure: true
    }
  
    const {accessToken, newrefreshToken} = await generateAccessAndRefreshTokens(user._id)
  
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newrefreshToken, options)
    .json(new ApiResponse(200, {accessToken, refreshToken: newrefreshToken}, "new tokens generated"))
  } catch (error) {
    
  }
})

const changePassword = asyncHandler(async(req, res) => {
  const {oldPassword, newPassword} = req.body
  const user = await User.findById(req.user._id)
 
  if(!user){   //additional check
    throw new ApiError(404, "user not found")
  }

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
  if(!isPasswordCorrect){
    throw new ApiError(400, "incorrect password")
  }
  user.password = newPassword
  await user.save({validateBeforeSave: false})
  return res
  .status(200)
  .json(new ApiResponse(200, {}, "password changed"))
})

const getCurrentUser = asyncHandler(async(req, res) => {
  return res
  .status(200)
  .json(new ApiResponse(200, req.user, "current user fetched successfully"))
})

const upadateAccountDetails = asyncHandler(async(req, res) => {
  const {fullname, email} = req.body
  if(!fullname || !email){
   throw new ApiError(400, "please provide all values")
  }
  const user = await User.findByIdAndUpdate(req.user?._id,
 { $set:{
    fullname: fullname,
    email: email
  }},
  {
    new: true

  }).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(200, user, "account details updated successfully"))
  
})

const updateUserAvatar = asyncHandler(async(req, res) => {
  const avatarLocalPath = req.file?.path

  if(!avatarLocalPath) {
    throw new ApiError(400, "please provide an avatar")
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath)
  if(!avatar.url) {
    throw new ApiError(400, "avatar upload failed")
  }
  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set:{
        avatar: avatar.url
      }
    },
    {
      new: true
    }
  ).select("-password")
  return res
  .status(200)
  .json(new ApiResponse(200, user, "avatar updated successfully"))
})

const updateUserCoverImage = asyncHandler(async(req, res) => {
  const coverImageLocalPath = req.file?.path

  if(!coverImageLocalPath) {
    throw new ApiError(400, "please provide an Cover Image")
  }
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)
  if(!coverImage.url) {
    throw new ApiError(400, "Cover Image upload failed")
  }
  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set:{
        coverImage: coverImage.url
      }
    },
    {
      new: true
    }
  ).select("-password")
  return res
  .status(200)
  .json(new ApiResponse(200, user, "Cover image updated successfully"))
})

const getUserChannelProfile = asyncHandler(async(req, res) => {
  const {username} = req.params
  if(!username?.trim()) {
    throw new ApiError(400, "please provide a username")
  }

  // use agergation pipeline to get the user channel profile
  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase()
      }
    },
    {
      $lookup: {
          from: "subscriptions",
          localField: "_id",
          foreignField: "channel",
          as: "subscribers"
      }
    },
    {
      $lookup: {
          from: "subscriptions",
          localField: "_id",
          foreignField: "subscriber",
          as: "subscribedTo"
      }
    },
    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers"
        },
        subscribedToCount: {
          $size: "$subscribedTo"
        },
        isSubscribed: {
          $cond: {
            if: {$in: [req.user?._id, "$subscribers.subscriber"]},
            then: true,
            else: false
          }
        }
      }
    },
    {
      $project: {
        fullname: 1,
        username: 1,
        email: 1,
        subscribersCount: 1,
        subscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
      }
    }
  ])

  if(!channel?.length){
    throw new ApiError( 404, "channel does not exist")
  }
  
 return res.status(200).json( 
  new ApiResponse(200, channel[0], "User Channel fetched successfully")
 )
})

const getWatchHistory = asyncHandler(async(req, res) => {
  const user = await User.aggregate([
      {
          $match: {
              _id: new mongoose.Types.ObjectId(req.user._id)
          }
      },
      {
          $lookup: {
              from: "videos",
              localField: "watchHistory",
              foreignField: "_id",
              as: "watchHistory",
              pipeline: [
                  {
                      $lookup: {
                          from: "users",
                          localField: "owner",
                          foreignField: "_id",
                          as: "owner",
                          pipeline: [
                              {
                                  $project: {
                                      fullName: 1,
                                      username: 1,
                                      avatar: 1
                                  }
                              }
                          ]
                      }
                  },
                  {
                      $addFields:{
                          owner:{
                              $first: "$owner"
                          }
                      }
                  }
              ]
          }
      }
  ])

  return res
  .status(200)
  .json(
      new ApiResponse(
          200,
          user[0].watchHistory,
          "Watch history fetched successfully"
      )
  )
})


export { 
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken, 
  changePassword,
  getCurrentUser,
  upadateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory
  };
