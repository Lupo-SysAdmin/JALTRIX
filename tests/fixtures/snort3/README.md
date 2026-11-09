# Captured from the actual engine

Generated on Kali 2026.3 with Snort 3.13.2.0 plus the appid linkage patch,
using tests/fixtures/lab/benign.pcap and local.rules through engine.replay().
Three benign packets; two matching alerts. The engine reports action `allow`:
these are detection events from passive offline replay, not blocked packets.
The initial capture used system DAQ 3.0.24; the isolated runtime is rebuilt
with DAQ 3.0.29 and revalidated separately. No hostile network traffic used.
