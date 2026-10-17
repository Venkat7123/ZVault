-- 05_revoke_admin.sql
-- Run while connected as SECADM1 (NOT as DB2INST1).
-- Removes security-admin power from the database admin.

REVOKE SECADM ON DATABASE FROM USER DB2INST1;

-- After: only SECADM1 should show SECADM = Y
SELECT VARCHAR(GRANTEE, 12) AS GRANTEE, SECURITYADMAUTH AS SECADM
FROM SYSCAT.DBAUTH WHERE SECURITYADMAUTH = 'Y';
