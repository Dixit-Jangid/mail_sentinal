import { useState } from "react";
import { KeyRound, LockKeyhole, Mail, ShieldCheck, UserRound } from "lucide-react";
import { authRequest } from "../services/authService";

export default function AuthPage({ onAuthenticated, initialError, onRetry }) {
  const [mode, setMode] = useState("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const isRegistering = mode === "register";

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const { user } = await authRequest(mode, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      });
      onAuthenticated(user);
    } catch (requestError) {
      setError(requestError.message || "Unable to reach the authentication service.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-screen">
      <section className="auth-card" aria-labelledby="auth-title">
        <img className="auth-logo" src="/mail-sentinel-logo.png" alt="MAIL SENTINEL logo" />
        <p className="auth-eyebrow">MAIL SENTINEL</p>
        <h1 id="auth-title">{isRegistering ? "Create your account" : "Welcome back"}</h1>
        <p className="auth-description">
          {isRegistering ? "Register to access your security workspace." : "Sign in to access your security workspace."}
        </p>

        <div className="auth-tabs" role="tablist" aria-label="Account access">
          <button
            type="button"
            role="tab"
            aria-selected={!isRegistering}
            className={!isRegistering ? "active" : ""}
            onClick={() => { setMode("login"); setError(""); }}
          >
            Login
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={isRegistering}
            className={isRegistering ? "active" : ""}
            onClick={() => { setMode("register"); setError(""); }}
          >
            Register
          </button>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          {isRegistering && (
            <label>
              <span>Name</span>
              <div className="auth-input-wrap">
                <UserRound size={17} />
                <input
                  autoComplete="name"
                  maxLength={80}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Your name"
                  required
                  value={name}
                />
              </div>
            </label>
          )}
          <label>
            <span>Email address</span>
            <div className="auth-input-wrap">
              <Mail size={17} />
              <input
                autoComplete="email"
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                required
                type="email"
                value={email}
              />
            </div>
          </label>
          <label>
            <span>Password</span>
            <div className="auth-input-wrap">
              <KeyRound size={17} />
              <input
                autoComplete={isRegistering ? "new-password" : "current-password"}
                minLength={isRegistering ? 8 : undefined}
                onChange={(event) => setPassword(event.target.value)}
                placeholder={isRegistering ? "At least 8 characters" : "Enter your password"}
                required
                type="password"
                value={password}
              />
            </div>
          </label>

          {(error || initialError) && (
            <div className="auth-error" role="alert">{error || initialError}</div>
          )}
          {initialError && onRetry && (
            <button className="auth-retry" type="button" onClick={onRetry}>Retry connection</button>
          )}
          <button className="auth-submit" disabled={loading} type="submit">
            <LockKeyhole size={16} />
            {loading ? "Please wait..." : isRegistering ? "Create account" : "Login"}
          </button>
        </form>

        <p className="auth-security-note">
          <ShieldCheck size={14} />
          Passwords are securely hashed on the server.
        </p>
      </section>
    </main>
  );
}
