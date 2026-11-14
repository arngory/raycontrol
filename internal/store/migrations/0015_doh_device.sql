-- DoH's token is the device's (docs/08-decisions.md, R4-37): no table
-- changes, the tokens are derived (store.DoHDeviceToken). The step of this
-- version (startDoHShared) opens the window in which a user's DoH secret,
-- which the subscriptions carried until now, is still a token. The
-- statement is only there for the migration to have one.
SELECT 1;
