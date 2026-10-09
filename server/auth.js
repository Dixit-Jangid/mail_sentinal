import { Buffer } from "node:buffer";
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { promises as fs } from "node:fs";
import process from "node:process";
import path from "node:path";
import express from "express";
import { fileURLToPath } from "node:url";

const scrypt = promisify(scryptCallback);
const router = express.Router();
const sessionCookie = "mail_sentinel_session";
const sessionLifetime = 7 * 24 * 60 * 60 * 1000;
const unknownEmailSalt = "4f2bb6cb14c1e7674ad2c51158fb4601";
const usersFile = process.env.MAIL_SENTINEL_AUTH_STORE
  || path.join(path.dirname(fileURLToPath(import.meta.url)), "data", "auth-users.json");
const sessions = new Map();
let accountOperations = Promise.resolve();

function serializeAccountOperation(operation) {
  const result = accountOperations.then(operation, operation);
  accountOperations = result.catch(() => {});
  return result;
}

async function readUsers() {
  try {
    const users = JSON.parse(await fs.readFile(usersFile, "utf8"));
    if (!Array.isArray(users)) throw new Error("Account store must contain a user list.");
    return users;
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function writeUsers(users) {
  const directory = path.dirname(usersFile);
  await fs.mkdir(directory, { recursive: true });
  const temporaryFile = `${usersFile}.${process.pid}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(users), { mode: 0o600 });
  await fs.rename(temporaryFile, usersFile);
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${sessionCookie}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetime / 1000}${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookie}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function getSessionToken(req) {
  return req.headers.cookie
    ?.split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${sessionCookie}=`))
    ?.slice(sessionCookie.length + 1);
}

function getSessionUser(req) {
  const token = getSessionToken(req);
  if (!token) return null;

  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session.user;
}

function publicUser(user) {
  return { name: user.name, email: user.email };
}

router.post("/register", async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!name || name.length > 80) {
    return res.status(400).json({ error: "Enter a name between 1 and 80 characters." });
  }
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }
  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "Password must be between 8 and 128 characters." });
  }

  try {
    const user = await serializeAccountOperation(async () => {
      const users = await readUsers();
      if (users.some((account) => account.email === email)) return null;

      const salt = randomBytes(16).toString("hex");
      const passwordHash = (await scrypt(password, salt, 64)).toString("hex");
      const account = { id: randomBytes(16).toString("hex"), name, email, salt, passwordHash };
      users.push(account);
      await writeUsers(users);
      return account;
    });

    if (!user) return res.status(409).json({ error: "An account with this email already exists." });

    const token = randomBytes(32).toString("hex");
    sessions.set(token, { user: publicUser(user), expiresAt: Date.now() + sessionLifetime });
    setSessionCookie(res, token);
    return res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    console.error("Account registration failed:", error);
    return res.status(500).json({ error: "Unable to create your account right now." });
  }
});

router.post("/login", async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!email || !password) {
    return res.status(400).json({ error: "Enter your email address and password." });
  }

  try {
    const user = await serializeAccountOperation(async () => {
      const users = await readUsers();
      const account = users.find((storedUser) => storedUser.email === email);
      if (!account) {
        await scrypt(password, unknownEmailSalt, 64);
        return null;
      }

      const candidate = await scrypt(password, account.salt, 64);
      const storedHash = Buffer.from(account.passwordHash, "hex");
      if (candidate.length !== storedHash.length || !timingSafeEqual(candidate, storedHash)) return null;
      return account;
    });

    if (!user) return res.status(401).json({ error: "Email or password is incorrect." });

    const token = randomBytes(32).toString("hex");
    sessions.set(token, { user: publicUser(user), expiresAt: Date.now() + sessionLifetime });
    setSessionCookie(res, token);
    return res.json({ user: publicUser(user) });
  } catch (error) {
    console.error("Account login failed:", error);
    return res.status(500).json({ error: "Unable to sign in right now." });
  }
});

router.get("/me", (req, res) => {
  return res.json({ user: getSessionUser(req) });
});

router.post("/logout", (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);
  clearSessionCookie(res);
  return res.json({ success: true });
});

export function createAuthRouter() {
  return router;
}
