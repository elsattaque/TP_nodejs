import "dotenv/config";
import express from "express";
import z from "zod";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import { connectDb } from "./lib.js";
import { validateData, logger, checkAuthForm, checkAuthEtud } from "./middleware.js";

const app = express();

let db = await connectDb();

const userSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(6),
    role: z.enum(["etudiant", "formateur"])
});

// Route POST /auth/signup qui permet d'ajouter un utilisateur avec les informations fournies
// au format JSON : name et email --
app.post(
    "/auth/signup",
    express.json(),
    validateData(userSchema),
    async (req, res) => {
        const data = req.body;
        try {
            const hashedPassword = await bcrypt.hash(data.password, 10);
            const [result] = await db.execute(
                "INSERT INTO user (name, email, password, role) VALUES (?, ?, ?, ?)",
                [data.name, data.email, hashedPassword, data.role]
            );

            res.status(200);
            res.json({ id: result.insertId, name: data.name, email: data.email, role: data.role });
        } catch (error) {
            res.status(500);
            res.json({ error: error.message });
        }
    }
);

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6)
});

// Route POST /auth/login pour s'authentifier
app.post(
    "/auth/login",
    express.json(),
    validateData(loginSchema),
    async (req, res) => {
        const data = req.body;

        // On vérifie en base de données si email + password sont OK
        const [rows] = await db.query(
            "SELECT id, password, role FROM user WHERE email = ?",
            [data.email]
        );

        if (rows.length === 0) {
            res.status(401);
            res.send("User not found");
            return;
        }

        const isRightPassword = await bcrypt.compare(
            data.password,
            rows[0].password
        );
        if (!isRightPassword) {
            res.status(401);
            res.send("Unauthorized");
            return;
        }

        // Générer un token JWT
        const payload = { id: rows[0].id, role: rows[0].role };
        const token = jwt.sign(payload, process.env.JWT_KEY);

        // Renvoyer le token si tout est OK
        res.json({ token });
    }
);

const sessionsSchema = z.object({
    email: z.string().email(),
    title: z.string().min(4),
    date_session: z.string().date()
});

// Route POST /sessions pour créer des nouvelles sessions en tant que formateur
app.post(
    "/sessions",
    express.json(),
    validateData(sessionsSchema),
    checkAuthForm,
    async (req, res) => {
        const data = req.body;

        // Récupération de l'id
        const [rows] = await db.query(
            "SELECT id FROM user WHERE email = ?",
            [data.email]
        );

        try {
            const id_formateur = rows[0].id;
            const [result] = await db.execute(
                "INSERT INTO session (title, date, formateur_id) VALUES (?, ?, ?)",
                [data.title, data.date_session, id_formateur]
            );

            res.status(200);
            res.json({ id: result.insertId, title: data.title, date: data.date_session, id_formateur: id_formateur });
        } catch (error) {
            res.status(500);
            res.json({ error: error.message });
        }
    }
);

// Route GET /sessions pour lister toutes les sessions
app.get(
    "/sessions",
    async (req, res) => {
        const [rows] = await db.query(
            "SELECT * FROM session"
        );

        // Formatage de la date en `YYYY-MM-DD` sinon 2024-12-08T23:00:00.000Z
        const formattedRows = rows.map((row) => {
            for (const key in row) {
                if (row[key] instanceof Date) {
                    row[key] = row[key].toISOString().split("T")[0];
                }
            }
            return row;
        });

        res.json(formattedRows);
    }
);

// Route GET /sessions/id pour lister les caractéristiques d'une session spécifique
app.get(
    "/sessions/:id(\\d+)",
    async (req, res) => {
        const id = parseInt(req.params.id);

        // Vérification que ce soit bien un fomrmateur
        const [rows] = await db.query(
            "SELECT * FROM session where id = ?",
            [id]
        );

        if (rows.length === 0) {
            res.status(404);
            res.send("Session not found");
            return;
        }

        // Formatage de la date en `YYYY-MM-DD` sinon 2024-12-08T23:00:00.000Z
        const formattedRows = rows.map((row) => {
            for (const key in row) {
                if (row[key] instanceof Date) {
                    row[key] = row[key].toISOString().split("T")[0];
                }
            }
            return row;
        });

        res.json(formattedRows);
    }
);

const modifSessionsSchema = z.object({
    newTitle: z.string().min(4),
    newDate_session: z.string().date(),
    newFormateurName: z.string().min(2)
});

// Route PUT /sessions/id pour modifier la session
app.put(
    "/sessions/:id(\\d+)",
    express.json(),
    checkAuthForm,
    validateData(modifSessionsSchema),
    async (req, res) => {
        const id_session = parseInt(req.params.id);

        const data = req.body;

        try {
            // Récupération de l'id du nouveau formateur par son nom
            const [formateur] = await db.execute(
                "SELECT id from user where name = ?",
                [data.newFormateurName]
            );

            // Vérification que le formateur existe bien
            if (formateur.length === 0) {
                res.status(404);
                res.send("User not found");
                return;
            };

            const id_formateur = formateur[0].id;

            const [result] = await db.execute(
                "UPDATE session SET title = ?, date = ?, formateur_id = ? WHERE id = ?",
                [data.newTitle, data.newDate_session, id_formateur, id_session]
            );

            res.status(200);
            res.json({ id: result.insertId, new_title: data.newTitle, new_date: data.newDate_session, new_id_formateur: id_formateur });
        } catch (error) {
            res.status(500);
            res.json({ error: error.message });
        }
    }
);

// Route DELETE /sessions/id pour supprimer la session
app.delete(
    "/sessions/:id(\\d+)",
    express.json(),
    checkAuthForm,
    async (req, res) => {
        const id_session = parseInt(req.params.id);

        try {
            const [result] = await db.execute(
                "DELETE FROM session WHERE id = ?",
                [id_session]
            );

            res.status(200);
            res.json({ id: result.insertId });
        } catch (error) {
            res.status(500);
            res.json({ error: error.message });
        }
    }
);

const emargementSchema = z.object({
    email: z.string().email()
});

// Route POST /sessions/id/emargement pour émarger les étudiants
app.post(
    "/sessions/:id(\\d+)/emargement",
    express.json(),
    checkAuthEtud,
    validateData(emargementSchema),
    async (req, res) => {
        const id_session = parseInt(req.params.id);

        const data = req.body;

        try {
            // Récupération de l'id du nouveau formateur par son nom
            const [rows] = await db.execute(
                "SELECT id from user where email = ?",
                [data.email]
            );

            // Vérification que le formateur existe bien
            if (rows.length === 0) {
                res.status(404);
                res.send("User not found");
                return;
            };

            const id_etudiant = rows[0].id;

            const [result] = await db.execute(
                "INSERT INTO emargement (session_id, etudiant_id, status) VALUES (?, ?, '1')",
                [id_session, id_etudiant]
            );

            res.status(200);
            res.json({ id: result.insertId, id_session: id_session, id_etudiant: id_etudiant, status: "1" });
        } catch (error) {
            res.status(500);
            res.json({ error: error.message });
        }
    }
);

// Route GET /sessions/id pour lister les caractéristiques d'une session spécifique
app.get(
    "/sessions/:id(\\d+)/emargement",
    checkAuthForm,
    async (req, res) => {
        const id = parseInt(req.params.id);

        const [rows] = await db.query(
            "SELECT u.name FROM user u INNER JOIN emargement e ON u.id = e.etudiant_id WHERE e.session_id = ?",
            [id]
        );

        res.json(rows);
    }
);

app.listen(3000, () => {
    console.log("Server is running on port 3000");
});