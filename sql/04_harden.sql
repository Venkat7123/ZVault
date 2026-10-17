-- 04_harden.sql
-- Run as DB2INST1 (the database creator), AFTER creating the OS user SECADM1.
--
-- Point 3: the AI gateway may no longer switch to AUDITOR1.
--          Auditors read the audit log directly, never through the AI.
-- Point 2: give "security admin" (SECADM) power to a separate account,
--          so the database admin cannot switch the protection rules off.
--          (Revoking it from DB2INST1 is done in 05, logged in as SECADM1.)

-- ---------- Before: who holds which power ----------
SELECT VARCHAR(GRANTEE, 12) AS GRANTEE, GRANTEETYPE AS T,
       SECURITYADMAUTH AS SECADM, DBADMAUTH AS DBADM,
       DATAACCESSAUTH AS DATAACCESS, ACCESSCTRLAUTH AS ACCESSCTRL
FROM SYSCAT.DBAUTH ORDER BY GRANTEE;

-- ---------- Point 3 ----------
ALTER TRUSTED CONTEXT AI_GATEWAY_CTX DROP USE FOR AUDITOR1;

-- ---------- Point 2, step 1 ----------
GRANT SECADM ON DATABASE TO USER SECADM1;
-- SECADM1 must be able to log in to run 05 (otherwise nobody could revoke).
GRANT CONNECT ON DATABASE TO USER SECADM1;

SELECT VARCHAR(GRANTEE, 12) AS GRANTEE, SECURITYADMAUTH AS SECADM
FROM SYSCAT.DBAUTH WHERE SECURITYADMAUTH = 'Y';
