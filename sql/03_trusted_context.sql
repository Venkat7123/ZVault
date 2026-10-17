-- 03_trusted_context.sql
-- The last-hop fix: the AI gateway (user AIGW) gets NO data access of its own.
-- It can only open a trusted connection from one address and switch to a
-- listed employee, so Db2 applies THAT employee's role and branch rules.

-- AIGW may connect, but has no table privileges -> on its own it sees nothing.
GRANT CONNECT ON DATABASE TO USER AIGW;

-- The gateway writes the audit log with its own identity (insert only).
GRANT INSERT ON BANK.ACCESS_LOG TO USER AIGW;
-- Only auditors may read the log.
GRANT SELECT ON BANK.ACCESS_LOG TO ROLE AUDITOR;

-- Trusted context: only AIGW, only from the Docker host address,
-- may switch to these employees (no password needed for the switch).
-- If your Docker gateway IP is not 172.17.0.1, change it below.
CREATE TRUSTED CONTEXT AI_GATEWAY_CTX
  BASED UPON CONNECTION USING SYSTEM AUTHID AIGW
  ATTRIBUTES (ADDRESS '172.17.0.1')
  ENABLE
  WITH USE FOR CLERK1   WITHOUT AUTHENTICATION,
               CLERK2   WITHOUT AUTHENTICATION,
               MANAGER1 WITHOUT AUTHENTICATION;
-- AUDITOR1 is deliberately NOT listed: auditors see all branches, so the
-- AI gateway must never be able to act as one. They read the log directly.
