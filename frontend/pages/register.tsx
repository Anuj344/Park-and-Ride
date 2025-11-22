import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import styles from "../styles/Auth.module.css";

export default function Register() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const API_URL = process.env.NEXT_PUBLIC_API_URL;

  useEffect(() => {
    if (!API_URL) {
      console.error("NEXT_PUBLIC_API_URL is not defined");
    }
  }, [API_URL]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!API_URL) return setError("Configuration error: API URL not set.");

    let res: Response;
    try {
      res = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
    } catch {
      return setError("Network error. Please try again.");
    }

    let body: any = {};
    try {
      body = await res.json();
    } catch {
      return setError("Unexpected server response.");
    }

    if (!res.ok) {
      if (Array.isArray(body.detail)) {
        return setError(
          body.detail
            .map((d: any) => `• ${d.loc.join(".")}: ${d.msg}`)
            .join("\n")
        );
      }
      if (typeof body.detail === "string") {
        return setError(body.detail);
      }
      return setError(`Register failed (${res.status})`);
    }

    alert("Registration successful! Please log in.");
    router.push("/login");
  }

  return (
    <div className={styles.container}>
      <h2 className={styles.title}>Create Account</h2>
      <form className={styles.form} onSubmit={onSubmit}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="email">Email</label>
          <input
            className={styles.input}
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="password">Password</label>
          <input
            className={styles.input}
            id="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <button className={styles.button} type="submit">Sign Up</button>
      </form>

      {error && <div className={styles.error}>{error}</div>}

      <p className={styles.link}>
        Already have an account? <Link href="/login">Log in</Link>
      </p>
    </div>
  );
}
