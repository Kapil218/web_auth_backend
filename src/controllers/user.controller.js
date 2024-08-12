import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const genrateAccessTokenAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = await user.genrateAccessToken(user._id);
    const refreshToken = await user.genrateRefreshToken(user._id);
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "some error occur while genrating access and refresh token"
    );
  }
};

// Register User
const registerUser = asyncHandler(async (req, res) => {
  // getting data from frontend
  const { username, email, password } = req.body;

  // validation check
  if ([username, email, password].some((field) => field?.trim == "")) {
    throw new ApiError(400, "All fields are required");
  }

  // check the user already present or not
  const exisetedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (exisetedUser) {
    throw new ApiError(409, "User with username or email already exists");
  }

  const user = await User.create({
    email,
    username: username.toLowerCase(),
    password,
  });
  const createdUser = await User.findById(user._id).select("-password");
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  //  return response
  return res
    .status(201)
    .json(new ApiResponse(201, createdUser, "User registered successfully"));
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
  // extracting data
  const { username, email, password } = req.body;
  //  check for empty data
  if (!username && !email) {
    throw new ApiError(400, "Username or email is required");
  }
  //  find the user
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (!user) {
    throw new ApiError(400, "User does not exists");
  }
  // check the password
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid User credentials");
  }
  // genrate access and refresh token and send as cookies
  const { accessToken, refreshToken } = await genrateAccessTokenAndRefreshToken(
    user._id
  );
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  const options = {
    httpOnly: true,
    secure: true,
    samesite: "None",
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged In successfully"
      )
    );
});

// Logout User
const logoutUser = asyncHandler(async (req, res) => {
  // clear cookies from client side and erase refresh token from server
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1, // this removes the field from document
      },
    },
    { new: true }
  );

  const options = {
    httpOnly: true,
    secure: true,
    samesite: "None",
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});

// const registerChallange = asyncHandler(async (req, res) => {
//   // clear cookies from client side and erase refresh token from server
//   const challangePayload = await generateRegistrationOptions({
//     rpId: "Localhost",
//     rpNmae: "My local host",
//     username: req.user.username,
//   });
//   await User.findByIdAndUpdate(
//     req.user._id,
//     {
//       $unset: {
//         refreshToken: 1, // this removes the field from document
//       },
//     },
//     { new: true }
//   );

//   const options = {
//     httpOnly: true,
//     secure: true,
//   };

//   return res
//     .status(200)
//     .clearCookie("accessToken", options)
//     .clearCookie("refreshToken", options)
//     .json(new ApiResponse(200, {}, "User logged out successfully"));
// });

export { registerUser, loginUser, logoutUser };
