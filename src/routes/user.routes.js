import { Router } from "express";
import {
  registerUser,
  loginUser,
  logoutUser,
  registerChallenge,
  verifyRegisterChallenge,
  verifyLoginChallenge,
  loginChallenge,
} from "../controllers/user.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/register-challenge").post(verifyJWT, registerChallenge);
router.route("/verify-challenge").post(verifyJWT, verifyRegisterChallenge);
router.route("/login-challenge").post(loginChallenge);
router.route("/login-verify").post(verifyLoginChallenge);

export default router;
