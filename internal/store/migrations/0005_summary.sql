-- R4-21: the client summaries (docs/08-decisions.md). Only counters by UTC
-- day, autonomous system and service: no addresses, no devices, no raw
-- reports. Kept 30 days.
--
-- svc 0 counts the reports themselves (field 'reports', and their network
-- type in 'net'); a service's rows count its observations: 'result'
-- (works, degraded, fails), 'udp' and 'mbps' buckets, 'stall' (the TCP
-- stall threshold in KiB).
CREATE TABLE summary_counts (
    day    INTEGER NOT NULL,
    asn    INTEGER NOT NULL,
    svc    INTEGER NOT NULL,
    field  TEXT NOT NULL,
    bucket TEXT NOT NULL,
    n      INTEGER NOT NULL,
    PRIMARY KEY (day, asn, svc, field, bucket)
) WITHOUT ROWID;

-- What the lookup said about an AS last: for the administrator's view.
CREATE TABLE summary_as (
    asn     INTEGER PRIMARY KEY,
    name    TEXT NOT NULL,
    country TEXT NOT NULL
);
