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

import base64
import hashlib
import os

import flask

HOST = os.getenv('HOST', None)
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
        <form action="{redirect_uri}" style="">
            <h1>fake-geoaxis</h1>
            <p>state: <input name="state" value="{state}"/></p>
            <p>redirect_uri: <code>{redirect_uri}</code></p>

            <h2>Scenarios</h2>

            <h3>Success</h3>
            <label><input name="code" type="radio" value="{noise}.CAROL_CARTOGRAPHER.{noise}" checked/>Authenticate as Persona 1</label>
            <label><input name="code" type="radio" value="{noise}.GEORGE_GEOGRAPHER.{noise}"/>Authenticate as Persona 2</label>
            <label><input name="code" type="radio" value="{noise}.OSCAR_OCEANOGRAPHER.{noise}"/>Authenticate as Persona 3</label>

            <h3>Errors</h3>
            <label><input name="code" type="radio" value="{noise}.raise_bad_code.{noise}"/>Auth Code Already Consumed</label>
            <label><input name="code" type="radio" value="{noise}.raise_bad_credentials.{noise}"/>Client Credentials Rejected</label>
            <label><input name="code" type="radio" value="{noise}.raise_bad_redirect_uri.{noise}"/>Redirect URI Rejected</label>
            <label><input name="code" type="radio" value="{noise}.raise_500.{noise}"/>HTTP 500</label>
            <label><input name="code" type="radio" value="{noise}.raise_501.{noise}"/>HTTP 501</label>
            <label><input name="code" type="radio" value="{noise}.raise_502.{noise}"/>HTTP 502</label>
            <label><input name="code" type="radio" value="{noise}.raise_503.{noise}"/>HTTP 503</label>

            <p><button>Authorize login, gogogo!</button></p>
        </form>
        <style>
            body {{ background-color: #36c; font: 12px Verdana; }}
            form {{ position: absolute; top: 10vh; left: 10vh; right: 10vh; bottom: 10vh; padding: 4em; background-color: white; box-shadow: 3px 3px 15px 5px rgba(0,0,0,.1); }}
            h1 {{ font: 100 50px Verdana; }}
            label {{ display: block; margin-left: 2em; }}
        </style>
    """.format(noise='0' * 30, state=state, redirect_uri=redirect_uri)


@app.route('/ms_oauth/oauth2/endpoints/oauthservice/tokens', methods=['POST'])
def issue_token():
    _inspect()
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
    elif not code:
        return flask.jsonify(error='invalid_request', error_description='Server received an unrecognized request'), 400

    return flask.jsonify({
        'expires_in': 3600,
        'token_type': 'Bearer',
        'access_token': base64.b64encode(code.replace('_', ' ').encode()).decode(),
    })


@app.route('/ms_oauth/resources/userprofile/me', methods=['GET'])
def get_profile():
    _inspect()
    auth_header = flask.request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return flask.jsonify(error='authentication failed'), 401

    try:
        full_name = base64.b64decode(auth_header[7:].encode()).decode().title()
        first_name, last_name = full_name.split()  # type: str, str
    except Exception as err:
        print(err)
        return flask.jsonify(error='token parse failed: {}'.format(err)), 500

    return flask.jsonify({
        'uid':             hashlib.sha1(full_name.encode()).hexdigest(),

        'ID':              '{}_{}'.format(first_name, last_name).lower(),
        'login':           '{}_{}'.format(first_name, last_name).lower(),
        'username':        '{}_{}'.format(first_name, last_name).lower(),

        'DN':              'cn={}, OU=People, OU=NGA, OU=DoD, O=U.S. Government, C=US'.format(full_name),
        'commonname':      full_name,
        'lastname':        last_name,
        'firstname':       first_name,

        'mail':            '{}{}@localhost'.format(first_name, last_name),
        'email':           '{}{}@localhost'.format(first_name, last_name),
        'personatypecode': 'AAA',
        'uri':             '/ms_oauth/resources/userprofile/me/{}'.format(hashlib.sha1(full_name.encode()).hexdigest()),
    })


def _inspect():
    print('-' * 80)
    print('HEADERS')
    print()
    for key, value in flask.request.headers.items():
        print('{:<14} : {}'.format(key, value))
    print()
    print('BODY')
    print()
    print(flask.request.get_data(as_text=True))
    print('-' * 80)


app.run(
    host=HOST,
    port=PORT,
    debug=True,
    ssl_context=(SSL_CERT, SSL_KEY) if SSL_CERT and SSL_KEY else None,
)
