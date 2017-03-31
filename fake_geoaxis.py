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
from base64 import b64decode
from pprint import pprint

import flask

PORT = 5001
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
    <body style="background-color: #36c; margin: 5em; font-family: Verdana;">
    <form action="{redirect_uri}" style="position: absolute; top: 5em; left: 5em; right: 5em; bottom: 5em; padding: 4em; background-color: white;">
        <h1 style="font: 100 50px Verdana">fake-geoaxis</h1>
        <p>state: <input name="state" value="{state}"/> <code style="color: #aaa">({state_decoded})</code></p>
        <p>redirect_uri: <code>{redirect_uri}</code></p>
        <p>code: <input name="code" value="pretendthisisavalidcode" style="font-family: monospace; width: 400px;"/></p>
        <p><button>Authorize login, gogogo!</button></p>
    </form>
    """.format(
        state=state,
        state_decoded=b64decode(state.encode()).decode(),
        redirect_uri=redirect_uri,
    )


@app.route('/ms_oauth/oauth2/endpoints/oauthservice/tokens', methods=['POST'])
def issue_token():
    print('-' * 80)
    print('HEADERS:')
    pprint(dict(flask.request.headers))
    print('BODY:')
    pprint(flask.request.get_data(as_text=True))
    print('-' * 80)
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
