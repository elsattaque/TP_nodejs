import mysql2 from "mysql2/promise";

async function connectDb() {
    let db = await mysql2.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      database: process.env.DB_DATABASE,
      password: process.env.DB_PASSWORD,
      timezone: "+01:00", // Utilise le fuseau horaire UTC+1
      dateStrings: true // Retourne les dates en texte brut
    });
  
    return db;
  }

  export { connectDb };