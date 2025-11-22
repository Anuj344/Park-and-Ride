// pages/api/subscribe.ts
import type { NextApiRequest, NextApiResponse } from "next";
import fs from "fs";
import path from "path";

const FILE_PATH = path.join(process.cwd(), "public", "subscribers.txt");

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST")
    return res.setHeader("Allow", "POST").status(405).end("Method Not Allowed");

  const { plate } = req.body;
  if (typeof plate !== "string")
    return res.status(400).json({ error: "Invalid plate" });

  const clean = plate.trim().toUpperCase();
  if (!/^[A-Z0-9\-]+$/.test(clean))
    return res.status(400).json({ error: "Bad characters in plate" });

  try {
    let data = "";
    try {
      data = await fs.promises.readFile(FILE_PATH, "utf8");
    } catch (err: any) {
      if (err.code !== "ENOENT") throw err;
    }
    const existing = new Set(
      data
        .split("\n")
        .map((l) => l.trim().toUpperCase())
        .filter(Boolean)
    );
    if (existing.has(clean))
      return res.status(409).json({ error: "Already a subscriber" });

    await fs.promises.appendFile(FILE_PATH, clean + "\n", "utf8");
    return res.status(201).json({ message: "Subscribed!" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not write file" });
  }
}