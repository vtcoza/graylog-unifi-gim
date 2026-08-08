# Field types

Graylog Open does not require Illuminate, but correct field types improve CIDR
searches, numeric aggregation, and timestamp handling. Create a field-type
profile from `schema/field-types.json`, assign it to the index set receiving the
UniFi streams, then rotate the active write index.

At minimum configure `source_ip` and `destination_ip` as IP, `event_created` as
date, and the documented counters/IDs as numeric. Apply mappings before ingest;
changing a populated field to an incompatible type can cause indexing failures.

Watch the Processing and Indexing Failures stream after deployment.

