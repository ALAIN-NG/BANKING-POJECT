#!/usr/bin/env bash
set -e
# Optional migrations / collectstatic controlled with env flags
if [ "$RUN_MIGRATIONS" = "1" ]; then
  python manage.py migrate --noinput
fi
if [ "$COLLECT_STATIC" = "1" ]; then
  python manage.py collectstatic --noinput
fi
exec "$@"
