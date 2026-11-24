-- hy2-obfs's salamander password is the device's
-- (docs/spec/salamander-device-v1.md): no table changes, the passwords are
-- derived (store.SalamanderDevicePassword). The step of this version
-- (startSalamanderShared) opens the window in which a service's S, which
-- the subscriptions carried until now, is still a password. The
-- statement is only there for the migration to have one.
SELECT 1;
