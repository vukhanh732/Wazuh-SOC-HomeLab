#!/bin/sh
# Install on the Linux agent as /var/ossec/active-response/bin/quarantine.sh.
# Edit these two lab paths for your agent before enabling Active Response.
exec /usr/bin/python3 /var/ossec/active-response/bin/quarantine.py \
  --watch-dir /home/vukhanh732/watch \
  --quarantine-dir /home/vukhanh732/quarantine \
  --execute
