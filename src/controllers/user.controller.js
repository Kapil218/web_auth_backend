import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
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

const registerChallenge = asyncHandler(async (req, res) => {
  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "web auth app",
    userName: req.user.username,
  });

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        registerChallenge: challengePayload.challenge,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { options: challengePayload },
        "User logged out successfully"
      )
    );
});

const verifyRegisterChallenge = asyncHandler(async (req, res) => {
  const { cred } = req.body;

  const challenge = req.user.registerChallenge;

  const verificatioResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
  });

  if (!verificatioResult.verified)
    return res.json({ error: "could not verify" });

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        passKey: verificatioResult.registrationInfo,
      },
      $unset: { registerChallenge: "" },
    },
    { new: true }
  ).select("-password");
  return res
    .status(200)
    .json(new ApiResponse(200, user, "User passkey stored"));
});

const loginChallenge = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "Username or email is required");
  }
  // Find the user based on the provided email
  const user = await User.findOne({
    email,
  });

  if (!user) {
    return res.status(404).json(new ApiResponse(404, null, "User not found"));
  }

  const options = await generateAuthenticationOptions({
    rpID: "localhost",
  });

  // Store the generated Challenge in the user's document
  await User.findByIdAndUpdate(
    user._id,
    {
      $set: {
        loginChallenge: options.challenge,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, { options }, "Login challenge generated"));
});

const verifyLoginChallenge = asyncHandler(async (req, res) => {
  const { cred, email } = req.body;
  // Find the user by email
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json(new ApiResponse(404, null, "User not found"));
  }

  const challenge = user?.loginChallenge;
  if (!challenge) {
    return res
      .status(400)
      .json(new ApiResponse(400, null, "No challenge found"));
  }

  try {
    const verificationResult = await verifyAuthenticationResponse({
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost:3000",
      expectedRPID: "localhost",
      response: cred,
      authenticator: {
        ...user.passKey,
        credentialPublicKey: new Uint8Array(
          user.passKey.credentialPublicKey.buffer
        ),
      },
    });

    if (!verificationResult.verified) {
      return res
        .status(401)
        .json(new ApiResponse(401, null, "Authentication failed"));
    }

    // Clear the stored challenge after successful verification
    await User.findByIdAndUpdate(
      user._id,
      { $unset: { loginChallenge: "" } },
      { new: true }
    ).select("-password");

    // genrate access and refresh token and send as cookies
    const { accessToken, refreshToken } =
      await genrateAccessTokenAndRefreshToken(user._id);
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
  } catch (error) {
    console.error("Verification Error:", error);
    return res
      .status(500)
      .json(new ApiResponse(500, null, "Verification process failed"));
  }
});

export {
  registerUser,
  loginUser,
  logoutUser,
  registerChallenge,
  verifyRegisterChallenge,
  verifyLoginChallenge,
  loginChallenge,
};
