import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import User from "../models/user.js";

// Log In = Sign In
export const signIn = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Cerchiamo con "User.findOne()" nel db la mail
    const existingUser = await User.findOne({ email });

    // La mail non esiste nel db
    if (!existingUser)
      return res.status(404).json({ mesage: "User doesn't exist." });

    // Compariamo con "bcrypt.compare()" le password "db e req"
    const isPassswordCorect = await bcrypt.compare(
      password,
      existingUser.password
    );

    // Le password "db e req" sono diverse
    if (!isPassswordCorect)
      return res.status(400).json({ message: "Invalid credentials." });

    // Creiamo il token con jwt.sign()
    const token = jwt.sign(
      { email: existingUser.email, id: existingUser._id },
      "test",
      { expiresIn: "1h" }
    );

    // Ritorniamo {utente, token}: se la mail e la password combacciano
    res.status(200).json({ result: existingUser, token });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong." });
  }
};

// Registrazione = SignUp
export const signUp = async (req, res) => {
  const { email, password, confirmPassword, firstName, lastName } = req.body;

  try {
    // cerchiamo nel db tramite mail l'utente
    const existingUser = await User.findOne({ email });

    // se esiste non deve registrarsi
    if (existingUser)
      return res.status(400).json({ mesage: "User already exists." });

    // La password e la confirmPassword devono essere uguali
    if (confirmPassword !== password)
      return res.status(400).json({ message: "The passwords don't match." });

    // Hashiamo la password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Creiamo l'utente nel db
    const result = await User.create({
      email,
      password: hashedPassword,
      name: `${firstName} ${lastName}`,
    });

    // Creiamo il token con jwt.sign()
    const token = jwt.sign({ email: result.email, id: result._id }, "test", {
      expiresIn: "1h",
    });

    // Consegniamo l'utente creato con il suo token
    res.status(200).json({ result, token });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong." });
  }
};
