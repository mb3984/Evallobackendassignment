import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../db.js";

export const register = (req, res) => {
  const { name, email, password } = req.body;

  const hash = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`,
    [name, email, hash],
    function (err) {
      if (err) return res.status(400).json({ message: "Email already exists" });

      res.json({ message: "User registered successfully" });
    }
  );
};

export const login = (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (!user) return res.status(401).json({ message: "User not found" });

    const match = bcrypt.compareSync(password, user.password_hash);

    if (!match) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "5h" }
    );

    res.json({ token });
  });
};

export const profile = (req, res) => {
  db.get(
    `SELECT id, name, email FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      res.json(user);
    }
  );
};
