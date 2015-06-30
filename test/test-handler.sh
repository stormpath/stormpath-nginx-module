#!/bin/bash

set -e
test "$VERBOSE" == "1" && set -x

# Make sure we've got the nginx binary ready
test -x nginx || exit 1

# Make sure there's no stale nginx test process running from previous attempt
fuser -n tcp 8000 -ks || true

valgrind -q --error-exitcode=1 ./nginx -c $PWD/conf/nginx.conf &
trap 'kill %1' EXIT
sleep 5

echo "TEST: using invalid Stormpath API credentials reports 500"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-invalid-credentials/ -u user:pass -o /dev/null)"
test "$status" == "500" || exit 1

echo "TEST: referencing nonexistent Stormpath application href reports 500"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-nonexistent-application/ -u user:pass -o /dev/null)"
test "$status" == "500" || exit 1

echo "TEST: client not supplying credentials immediately gets 401 response"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-auth/ -o /dev/null)"
test "$status" == "401" || exit 1

echo "TEST: client supplying incorrect credentials gets 401 response"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-auth/ -u fakeuser:fakepass -o /dev/null)"
test "$status" == "401" || exit 1

echo "TEST: client supplying correct credentials gets 200 response"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-auth/ -u 'nginx:Nginx4eva!' -o /dev/null)"
test "$status" == "200" || exit 1

echo "TEST: authenticated but not authorized client gets 401 response"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-group/ -u 'nginx2:Nginx4eva!' -o /dev/null)"
test "$status" == "401" || exit 1

echo "TEST: authenticated and authorized client gets 200 response"
status="$(curl -sw '%{http_code}' http://127.0.0.1:8000/test-group/ -u 'nginx:Nginx4eva!' -o /dev/null)"
test "$status" == "200" || exit 1

trap - EXIT
kill %1
wait %1

# Clean up: make absolutely sure there's no stale nginx test process running
fuser -n tcp 8000 -ks || true
