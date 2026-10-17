import { useNavigate } from "react-router-dom";
import { branchLabel } from "../branches";
import { useSession } from "../session";
import { formatClock } from "../timing";

const WARN_MS = 60_000;

export function SessionBadge() {
  const { session, clock, signOut } = useSession();
  const navigate = useNavigate();
  if (!session) return null;

  function leave() {
    signOut("You signed out.");
    navigate("/signin");
  }

  return (
    <div className="session" aria-label="Your session">
      <div className="session-who">
        <strong>{session.user.sub}</strong>
        <span className="muted">
          {" "}{session.user.role ?? "?"} · {branchLabel(session.user.branch)}
        </span>
      </div>
      {clock && (
        <div className="session-timers">
          <span className={clock.idleLeftMs < WARN_MS ? "timer warn" : "timer"} role="timer" aria-live="off">
            Idle sign-out in {formatClock(clock.idleLeftMs)}
          </span>
          <span className={clock.tokenLeftMs < WARN_MS ? "timer warn" : "timer"} role="timer" aria-live="off">
            Token expires in {formatClock(clock.tokenLeftMs)} (hard limit)
          </span>
        </div>
      )}
      <button type="button" className="btn btn-ghost" onClick={leave}>Sign out</button>
    </div>
  );
}
