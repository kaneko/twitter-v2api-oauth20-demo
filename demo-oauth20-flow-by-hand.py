#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import json
import base64
import string
import hashlib
import pathlib
import secrets
import urllib.parse
import urllib.request

def load_config(config_path):
	with open(config_path) as f:
		return json.load(f)
	pass  # with
pass  # def

def json_dumps_beauty(data):
	return json.dumps(data, ensure_ascii = False, indent = 4)
pass  # def

def make_basic_auth_headers(username, password):
	credential = "{}:{}".format(username, password)
	authorization = base64.b64encode(credential.encode("utf-8")).decode("utf-8")

	return {
		"Content-Type": "application/x-www-form-urlencoded",
		"Authorization": "Basic {}".format(authorization)
	}
pass  # def

def make_random_string(length):
	chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
	chars += "_-."

	return "".join(secrets.choice(chars) for x in range(length))
pass  # def

def make_code_challenge(code_verifier):
	code_challenge_sha256 = hashlib.sha256(code_verifier.encode()).digest()
	code_challenge = base64.urlsafe_b64encode(code_challenge_sha256).decode().rstrip("=")

	return code_challenge
pass  # def

def make_authorize_request(client_id, redirect_uri, scopes):
	endpoint = "https://twitter.com/i/oauth2/authorize"

	state = make_random_string(64)
	code_verifier = make_random_string(128)
	code_challenge = make_code_challenge(code_verifier)

	params = {
	    "client_id": client_id,
	    "redirect_uri": redirect_uri,
	    "state": state,
	    "scope": " ".join(scopes),
	    "response_type": "code",
	    "code_challenge": code_challenge,
	    "code_challenge_method": "S256"
	}

	query_string = urllib.parse.urlencode(
		params,
		quote_via = urllib.parse.quote
	)

	request_url = "{url}?{params}".format(
		url = endpoint,
		params = query_string
	)

	session_data = {
		"code_verifier": code_verifier,
		"request_url": request_url
	}
	session_data.update(params)

	d = json_dumps_beauty(session_data)
	print(d)

	with open("authorization-request.json", "w") as f:
		print(d, file = f)
	pass  # with

	print("[Authorize Request URL]")
	print("=" * 70)
	print(request_url)
	print("=" * 70)

	return (state, code_verifier, request_url)
pass  # def

def get_access_token(client_id, client_secret, redirect_uri, code_verifier, code):
	endpoint = "https://api.twitter.com/2/oauth2/token"

	headers = make_basic_auth_headers(client_id, client_secret)

	payload = {
		"client_id": client_id,
		"client_secret": client_secret,
		"redirect_uri": redirect_uri,
		"grant_type": "authorization_code",
		"code": code,
		"code_verifier": code_verifier
	}

	data = urllib.parse.urlencode(payload, quote_via = urllib.parse.quote)
	data = data.encode("utf-8")

	print("=" * 40)
	print("Get access token params (Payload): ")
	print(json_dumps_beauty(payload))
	print("=" * 40)

	request = urllib.request.Request(
		endpoint,
		headers = headers,
		data = data,
		method = "POST"
	)

	with urllib.request.urlopen(request) as response:
		body_str = response.read().decode("utf-8")
		body = json.loads(body_str)
	pass  # with

	with open("access-token.json", "w") as f:
		print(body_str, file = f)
	pass  # with

	print(json_dumps_beauty(body))

	return body
pass  # def

def do_refresh_token(client_id, client_secret, refresh_token):
	endpoint = "https://api.twitter.com/2/oauth2/token"

	headers = make_basic_auth_headers(client_id, client_secret)

	payload = {
		"client_id": client_id,
		"grant_type": "refresh_token",
		"refresh_token": refresh_token
	}

	data = urllib.parse.urlencode(payload, quote_via = urllib.parse.quote)
	data = data.encode("utf-8")

	request = urllib.request.Request(
		endpoint,
		headers = headers,
		data = data,
		method = "POST"
	)

	with urllib.request.urlopen(request) as response:
		body_str = response.read().decode("utf-8")
		body = json.loads(body_str)
	pass  # with

	with open("refresh-token.json", "w") as f:
		print(body_str, file = f)
	pass  # with

	print(json_dumps_beauty(body))

	return body
pass  # def

def main(argc, argv):
	config_path = pathlib.Path("config.json")
	config = load_config(config_path)

	client_id = config.get("twitter_client_id")
	client_secret = config.get("twitter_client_secret")
	redirect_uri = config.get("twitter_redirect_uri")
	scopes = config.get("twitter_scopes")

	state, code_verifier, request_url = make_authorize_request(
		client_id,
		redirect_uri,
		scopes
	)

	url = input("Paste reqidrected URL here\n=> ")
	url = url.strip()

	parsed = urllib.parse.urlparse(url)
	query_d = urllib.parse.parse_qs(parsed.query)
	auth_code = query_d.get("code")[0]
	state_received = query_d.get("state")[0]

	if state_received == state:
		body = get_access_token(
			client_id,
			client_secret,
			redirect_uri,
			code_verifier,
			auth_code	
		)
	pass  # if

	#refresh_token = body.get("refresh_token")
	#do_refresh_token(client_id, client_secret, refresh_token)
pass  # def

if __name__ == "__main__":
	main(len(sys.argv), sys.argv)
pass  # if

# [EOF]
