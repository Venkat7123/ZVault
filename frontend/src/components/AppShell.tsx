import { Link, NavLink, Outlet } from "react-router-dom";
import { useSession } from "../session";
import { Logo } from "./Logo";
import { SessionBadge } from "./SessionBadge";

export function AppShell() {
  const { session } = useSession();
  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="topbar">
        <Link to="/" className="brand">
          <Logo />
          <span className="brand-name">ZVault</span>
          <span className="brand-tag">Secure AI assistant for banks</span>
        </Link>
        <nav aria-label="Main" className="nav">
          <NavLink to="/assistant">Assistant</NavLink>
          <NavLink to="/documents">Documents</NavLink>
          {session?.user.role === "MANAGER" && <NavLink to="/privacy">Privacy</NavLink>}
          <NavLink to="/how-it-works">How it works</NavLink>
          <NavLink to="/limits">Limits</NavLink>
        </nav>
        {session ? <SessionBadge /> : <Link className="btn btn-ghost" to="/signin">Sign in</Link>}
      </header>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="footer">
        Demo bank: Bots Bank. IBM Granite and Db2 on IBM Z (LinuxONE). All data is synthetic.
      </footer>
    </>
  );
}
