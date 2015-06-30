#!/bin/bash

set -e
test "$VERBOSE" == "1" && set -x

# Make sure we've got the nginx binary ready
test -x nginx || exit 1

echo "TEST: auth_stormpath conf directive with no arguments fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-no-arguments.conf 2>&1)" && exit 1
[[ "$log" =~ 'invalid number of arguments in "auth_stormpath" directive' ]] || exit 1

echo "TEST: auth_stormpath conf directive with non-app href fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-invalid-app-href.conf 2>&1)" && exit 1
[[ "$log" =~ 'invalid application href "https://example.com/api/"' ]] || exit 1

echo "TEST: auth_stormpath_apikey conf directive with no arguments fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-apikey-no-arguments.conf 2>&1)" && exit 1
[[ "$log" =~ 'invalid number of arguments in "auth_stormpath_apikey" directive' ]] || exit 1

echo "TEST: auth_stormpath_apikey with nonexistent file fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-no-apikey-file.conf 2>&1)" && exit 1
[[ "$log" =~ 'Stormpath API properties file open failed' ]] || exit 1

echo "TEST: auth_stormpath_apikey with invalid file fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-invalid-apikey-file.conf 2>&1)" && exit 1
[[ "$log" =~ 'directive apiKey id or secret not found in properties file' ]] || exit 1

echo "TEST: auth_stormpath_require_group conf directive with no arguments fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-group-no-arguments.conf 2>&1)" && exit 1
[[ "$log" =~ 'invalid number of arguments in "auth_stormpath_require_group" directive' ]] || exit 1

echo "TEST: auth_stormpath_require_group conf directive with non-group href fails"
log="$(./nginx -t -c $PWD/conf/test-conf-auth-stormpath-invalid-group-href.conf 2>&1)" && exit 1
[[ "$log" =~ 'invalid group href' ]] || exit 1

echo "TEST: valid directives accepted"
log="$(./nginx -t -c $PWD/conf/nginx.conf 2>&1)" || exit 0
