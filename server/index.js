import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import cors from "cors";
import postRoutes from "./routes/posts.js";
import userRoutes from "./routes/users.js";
import dotenv from "dotenv";

dotenv.config();
const app = express();

app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "30mb", extended: true }));
app.use(cors());

app.get('/', (req,res)=>{
  res.send('App is running')
})


const CONNECTION_URL =
  "mongodb+srv://cerneavschivsevolod:Aaabbbccc111...@cluster0.9wmk0.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";
const PORT = process.env.PORT || 5000;

app.use("/posts", postRoutes);
app.use("/user", userRoutes);

// connettiti al "db" ascoltando la "porta"
mongoose
  .connect(process.env.CONNECTION_URL)
  .then(() =>
    app.listen(PORT, () =>
      console.log(`Server running on port http://localhost:${PORT}`)
    )
  )
  .catch((error) => console.log(`${error} did not connect`));
