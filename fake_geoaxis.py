# Copyright 2017, RadiantBlue Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import os
from pprint import pprint

import flask

PORT = int(os.getenv('PORT', 5001))
SSL_CERT = os.getenv('SSL_CERT')
SSL_KEY = os.getenv('SSL_KEY')

app = flask.Flask(__name__)


@app.route('/')
def index():
    links = []

    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        if endpoint not in globals():
            continue
        url = flask.url_for(endpoint)
        links.append('<li><a href="{}">{}</a></li>'.format(url, endpoint))
    return """
        <h1>Registered Routes</h1>
        <ul>
            {links}
        </ul>
    """.format(links=''.join(links))


@app.route('/ms_oauth/oauth2/endpoints/oauthservice/authorize', methods=['GET'])
def authorize_form():
    state = flask.request.args.get('state', '')
    redirect_uri = flask.request.args.get('redirect_uri')
    return """
    <body style="background-color: #36c; font: 12px Verdana;">
    <form action="{redirect_uri}" style="position: absolute; top: 10vh; left: 10vh; right: 10vh; bottom: 10vh; padding: 4em; background-color: white; box-shadow: 3px 3px 15px 5px rgba(0,0,0,.1);">
        <h1 style="font: 100 50px Verdana">fake-geoaxis</h1>
        <p>state: <input name="state" value="{state}"/></p>
        <p>redirect_uri: <code>{redirect_uri}</code></p>
        <p>
            Simulate Outcome:
            <div style="margin-left: 2em;">
                <label><input name="code" checked type="radio" value="{noise}.success.{noise}"/>Success</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_bad_code.{noise}"/>Auth Code Already Consumed</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_bad_credentials.{noise}"/>Client Credentials Rejected</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_bad_redirect_uri.{noise}"/>Redirect URI Rejected</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_500.{noise}"/>HTTP 500</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_501.{noise}"/>HTTP 501</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_502.{noise}"/>HTTP 502</label><br/>
                <label><input name="code" type="radio" value="{noise}.raise_503.{noise}"/>HTTP 503</label><br/>
            </div>
        </p>
        <p><button>Authorize login, gogogo!</button></p>
    </form>
    """.format(noise='0' * 30, state=state, redirect_uri=redirect_uri)


@app.route('/ms_oauth/oauth2/endpoints/oauthservice/tokens', methods=['POST'])
def issue_token():
    print('-' * 80)
    print('HEADERS:')
    pprint(dict(flask.request.headers))
    print('BODY:')
    pprint(flask.request.get_data(as_text=True))
    print('-' * 80)

    code = flask.request.form.get('code', '').strip('0').strip('.')  # type: str
    if code.startswith('raise_'):
        code = code[6:]
        print('Simulating callback failure')
        if code == 'bad_code':
            return flask.jsonify(error='invalid_grant', error_description='Invalid Grant: grant has been revoked'), 401
        elif code == 'bad_credentials':
            return flask.jsonify(error='invalid_client', error_description='Invalid client credentials'), 401
        elif code == 'bad_redirect_uri':
            return flask.jsonify(error='invalid_client', error_description='redirect_uri parameter value is invalid'), 401
        return flask.jsonify(error='oh no'), int(code) if code.isdigit() else 500

    return flask.jsonify({
        'expires_in': 3600,
        'token_type': 'Bearer',
        'access_token': 'ACCESS_TOKEN_TIME!',
    })


@app.route('/ms_oauth/resources/userprofile/me', methods=['GET'])
def get_profile():
    print('-' * 80)
    print('HEADERS:')
    pprint(dict(flask.request.headers))
    print('BODY:')
    pprint(flask.request.get_data(as_text=True))
    print('-' * 80)

    if flask.request.headers.get('Authorization') != 'Bearer ACCESS_TOKEN_TIME!':
        return flask.jsonify(error='sorry, bad token'), 401

    return flask.jsonify({
        "uid": "FAKEGEOAXIS",
        "mail": "FAKEGEOAXIS@localhost",
        "username": "FAKEGEOAXIS",
        "DN": "cn=FAKEGEOAXIS, OU=People, OU=NGA, OU=DoD, O=U.S. Government, C=US",
        "email": "FAKEGEOAXIS@localhost",
        "ID": "FAKEGEOAXIS",
        "lastname": "FAKEGEOAXIS",
        "login": "FAKEGEOAXIS",
        "commonname": "FAKEGEOAXIS",
        "firstname": "FAKEGEOAXIS",
        "personatypecode": "AAA",
        "uri": "/ms_oauth/resources/userprofile/me"
    })


app.run(
    port=PORT,
    debug=True,
    ssl_context=(SSL_CERT, SSL_KEY) if SSL_CERT and SSL_KEY else None,
)
