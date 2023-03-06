const express = require("express");
const app = express();
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const authRoute = require("./controllers/auth");
const cors = require('cors');
const corsOptions = require('./config/corsOptions');
const credentials = require('./middlewares/credentials');
const verifyToken = require('./middlewares/verifyToken');
const cookieParser = require('cookie-parser');

dotenv.config();

mongoose.connect(process.env.MONGO_URL).then(() => {
    console.log("Connected to MongoDB");
});

app.use(credentials);
app.use(cors(corsOptions));
app.use(express.json());
app.use(helmet());
app.use(morgan("common"));
app.use(cookieParser());

app.use("/api/auth", authRoute);

app.listen(8080, () => {
  console.log("Backend server is running");
});
