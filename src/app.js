import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

// Enable CORS
app.use(
  cors({
    origin: [`http://localhost:3000`],
    credentials: true,
  })
);

// Parse JSON and URL-encoded bodies
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ limit: "16kb" }));

// Parse cookies
app.use(cookieParser());

// Serve static files
app.use(express.static("public"));

// Routes import
import userRouter from "./routes/user.routes.js";
// Route handling
app.use("/api/v1/users", userRouter);

export { app };
