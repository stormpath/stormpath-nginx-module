# Stormpath Nginx module

This module provides client authorization using the
[Stormpath](https://stormpath.com/) authentication service.

The module is based on nginx' builtin
[auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module, but fires the authorization sub-request to Stormpath API instead.

The module provides authorization by extracting the client's username and
password from the HTTP basic auth headers they have provided, and making a
[login attempt](http://docs.stormpath.com/rest/product-guide/#application-account-authc) against a specific Stormpath application.

*WARNING: this is an experimental module, and is not yet ready to be used
in production, a lot of things are missing, it will not properly protect
your resources yet, is insecure and it may eat your coworkers. There, you
have been warned.*

## Installation

The module has been tested with nginx 1.9.1. As nginx modules need to be
compiled in, you'll need nginx source code as well.

Installation procedure:

Ensure that you have all the nginx build-time dependencies installed. If you're
on Debian or Ubuntu based system, you can accomplish this easily with:

    apt-get build-dep nginx

Get the latest Stormpath nginx module source code:

    git clone git@github.com:stormpath/stormpath-nginx-module.git

Get the latest nginx source code:

    wget http://nginx.org/download/nginx-1.9.1.tar.gz
    tar xzf nginx-1.9.1.tar.gz

Configure nginx with the modules you need, build it, and install it:

    cd nginx-1.9.1
    ./configure --with-http_ssl_module --add-module=../stormpath-nginx-module
    make
    make install

For real builds you're likely to need a lot more options (if you have nginx
binary on your system already, you can run `nginx -V` to see all the configure
flags used) - see the [nginx documentation](http://nginx.org/en/docs/configure.html)
for details.

## Configuration

If you have not already configured your Stormpath applications, directories,
and accounts, do so now. For the nginx configuration, you'll need your
API key ID and SECRET handy, as well as the `href` of the application to
authorize against.

To enable Stormpath authorization for a specific location block inside nginx
config, add the following two settings:

    auth_stormpath https://api.stormpath.com/v1/applications/YOUR-APP-HREF;
    auth_stormpath_apikey /path/to/your/apiKey.properties;

## Group membership check

In addition to authentication against an application, you can also require
the authenticated account to be a member of a particular group. To configure
this, use the `auth_stormpath_require_group` directive:

    auth_stormpath_require_group https://api.stormpath.com/v1/groups/YOUR-GROUP-HREF;

## Testing

The module comes with a small suite of tests to verify it's building and
working properly. To run the tests, you'll need a set of Stormpath credentials
(don't use the ones you use for production!). The test will create `nginxtest`
application, a group and a couple of users used in the test.

Test runner depends on Stormpath Python SDK (available as package `stormpath`
from Python Package Index), `curl` command-line tool, Valgrind (for
memory debugging), and all the build-dependencies of Nginx itself. On
Debian/Ubuntu system, these can be installed with:

    apt-get build-dep nginx
    apt-get install python-pip curl valgrind
    pip install stormpath

To run the test, first make sure your Stormpath test credentials are available
in the environment:

    export STORMPATH_API_KEY_ID=<your-test-api-key-id>
    export STORMPATH_API_KEY_SECRET=<your-test-api-key-secret>

Additionally, set the `VERBOSE` environment variable to `1` to see the verbose
test output (each line of each test as it executes):

    export VERBOSE=1

Then, run the tests with:

    make test

Note that during the test, nginx will temporarily listen on port 8000 for
incoming connections.

## Known issues

This is far, far away from complete module, it's more like a prototype to test
the waters. Biggest known problems with the module as is:

* doesn't cache Stormpath API responses, so an API call will be made for
  *every* request made for the location
* reinvents HTTP request creation and parsing, and Java .properties file parsing,
  probably containing nasty bugs in related portions of code

## Copyright

Copyright &copy; 2015 Stormpath, Inc. and contributors.

For all additional information, please see the full [Project Documentation](http://docs.stormpath.com/rest/product-guide/).

This project is open-source via the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

It is is heavily based upon the nginx source code, &copy; Nginx, Inc.

This project contains full copy of [json-parser](https://github.com/udp/json-parser/tree/c967d4d86788c50352e8ea4d67c64808a49c6650). &copy; 2012, 2013 James McLaughlin et al.
