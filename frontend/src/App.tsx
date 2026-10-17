import { Link, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { AssistantPage } from "./pages/AssistantPage";
import { HowItWorksPage } from "./pages/HowItWorksPage";
import { LimitsPage } from "./pages/LimitsPage";
import { SignInPage } from "./pages/SignInPage";

function NotFound() {
  return (
    <section className="center">
      <div className="card signin">
        <h1>Page not found</h1>
        <Link to="/assistant">Go to the assistant</Link>
      </div>
    </section>
  );
}

// The gateway returns index.html only for "/", /signin, /assistant, /how-it-works and /limits.
export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/assistant" replace />} />
        <Route path="signin" element={<SignInPage />} />
        <Route path="assistant" element={<AssistantPage />} />
        <Route path="how-it-works" element={<HowItWorksPage />} />
        <Route path="limits" element={<LimitsPage />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
