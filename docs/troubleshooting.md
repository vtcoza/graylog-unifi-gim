# Troubleshooting

## All messages are absent

- Confirm UniFi is sending UDP to the selected host/port.
- Confirm the Raw/Plaintext input is running and has `unifi_ingest=true`.
- Confirm Pipeline Processor is enabled after Message Filter Chain.

## Messages only appear as unsupported

Open the Parser Health dashboard and compare the raw envelope with a fixture.
Do not discard the message. Contribute a sanitized signature if it represents a
new firmware or event family.

## Lookup errors

Verify the CSV mount exists at `/usr/share/graylog/data/unifi-gim/` on every
Graylog node, is readable by UID 1100, and uses the committed headers.

## Indexing failures

Check the field-type profile and rotate after corrections. A field previously
indexed as a keyword cannot become an IP or number inside the same index.

## CEF fields are missing

Confirm the input is Raw/Plaintext UDP and the message still contains the
literal `CEF:` header. A CEF input or extractor may consume/change the payload
before this pipeline sees it.

