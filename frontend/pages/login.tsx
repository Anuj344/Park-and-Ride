import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import styles from "../styles/Auth.module.css";

export default function LoginPage() {
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<string | null | undefined>(undefined);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = localStorage.getItem("token");
    setToken(t);
    setLoading(false);
  }, []);

  useEffect(() => {
    if (!loading && token) {
      router.replace("/dashboard");
    }
  }, [loading, token, router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const API = process.env.NEXT_PUBLIC_API_URL;
    if (!API) {
      setError("Missing API URL");
      return;
    }

    let res: Response;
    try {
      res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
    } catch {
      setError("Could not connect to server");
      return;
    }

    let payload: any = {};
    try {
      payload = await res.json();
    } catch {
      setError("Invalid server response");
      return;
    }

    if (!res.ok) {
      setError(payload.detail || "Login failed");
      return;
    }

    localStorage.setItem("token", payload.access_token);
    router.replace("/dashboard");
  }

  if (loading || token) return null;

  return (
    <div className={styles.container}>
      <h2 className={styles.title}>Log In</h2>
      <form className={styles.form} onSubmit={handleSubmit}>
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

        <button className={styles.button} type="submit">Log In</button>
      </form>

      {error && <div className={styles.error}>{error}</div>}

      <p className={styles.link}>
        Don't have an account? <Link href="/register">Sign up</Link>
      </p>
    </div>
  );
}
