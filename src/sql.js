import { DatabaseSync } from 'node:sqlite';

export function createDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, is_admin INTEGER NOT NULL);
    INSERT INTO users (name, is_admin) VALUES ('alice', 1), ('bob', 0);
  `);
  return db;
}

// UNSAFE: string concatenation. name = "' OR '1'='1" returns every user.
export function findUserUnsafe(db, name) {
  return db.prepare(`SELECT name FROM users WHERE name = '${name}'`).all().map((r) => r.name);
}

// SAFE: placeholder. The value is sent separately from the SQL text,
// so it can never change the shape of the query.
export function findUserSafe(db, name) {
  return db.prepare('SELECT name FROM users WHERE name = ?').all(name).map((r) => r.name);
}
