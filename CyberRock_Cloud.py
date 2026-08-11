"""
CyberRock_Cloud.py
------------------
HTTP client for the CyberRock Cloud device API.

Provides thin wrappers around the CyberRock REST endpoints covering the full
range of authentication and key-wrapping flows supported by the platform:

	- Device login and session management
	- Token authentication (standard and EK variants):
		request challenge word (CW) → submit response word (RW) → poll status
	- Host authentication (priority and async variants)
	- HRW (Host Response Word) generation, including priority and EK variants
	- Daisy-chain authentication across token chains
	- Secure Boot attestation (CW/RW exchange and host-side verification)
	- Tenant login and token claiming

Each async flow follows a three-step pattern:
	1. Request  — submit inputs, receive a transactionId
	2. Reply    — submit the token response (where applicable)
	3. Status   — poll until the cloud returns a terminal status

EK variants additionally return an Enclave Key (EK) from the HSM-backed
CyberRock-Enclave, for flows that require HSM-side key derivation.

Priority variants give their result in step 2.

Dependencies:
	requests, time

Configuration:
	Set the target environment in CyberRock_Config.py).
"""

import time, requests

from CyberRock_Config import get_environment_url
environmentURL = get_environment_url()

cyberrock_device_login =                     environmentURL + 'api/auth/deviceLogin'

cyberrock_device_tokenauth_requestcw =       environmentURL + 'api/device/requestCW'
cyberrock_device_tokenauth_replyrw =         environmentURL + 'api/device/replyRW'
cyberrock_device_tokenauth_checkstatus =     environmentURL + 'api/device/checkAuthStatus'

cyberrock_device_tokenauthEK_requestcw =     environmentURL + 'api/device/EKrequestCW'
cyberrock_device_tokenauthEK_replyrw =       environmentURL + 'api/device/EKreplyRW'
cyberrock_device_tokenauthEK_checkstatus =   environmentURL + 'api/device/EKCheckAuthStatus'

cyberrock_device_hostauth_request =          environmentURL + 'api/device/requestHostAuth'
cyberrock_device_hostauth_checkstatus =      environmentURL + 'api/device/checkRequestHostAuthStatus'

cyberrock_device_priorityhostauth =          environmentURL + 'api/device/priorityHostAuth'

cyberrock_device_hostauthEK_request =        environmentURL + 'api/device/EKrequestHostAuth'
cyberrock_device_hostauthEK_checkstatus =    environmentURL + 'api/device/EKcheckRequestHostAuthStatus'

cyberrock_device_EKpriorityhostauth =        environmentURL + 'api/device/EKpriorityHostAuth'

cyberrock_device_requestHRW =                environmentURL + 'api/device/requestHRW'
cyberrock_device_requestHRWstatus =          environmentURL + 'api/device/checkRequestHRWStatus'

cyberrock_device_priorityrequestHRW =        environmentURL + 'api/device/priorityRequestHRW'

cyberrock_device_EKrequestHRW =              environmentURL + 'api/device/EKrequestHRW'
cyberrock_device_EKrequestHRWstatus =        environmentURL + 'api/device/EKcheckRequestHRWStatus'

cyberrock_device_EKpriorityrequestHRW =      environmentURL + 'api/device/EKpriorityRequestHRW'

cyberrock_device_requestSecureBootAttestationCW =		environmentURL + 'api/device/requestSecureBootAttestationCW'
cyberrock_device_replySecureBootAttestationRW   =		environmentURL + 'api/device/replySecureBootAttestationRW'
cyberrock_device_checkRequestSecureBootAttestationStatus =      environmentURL + 'api/device/checkRequestSecureBootAttestationStatus'

cyberrock_device_requestDaisyChainCW =		environmentURL + 'api/device/requestDaisyChainCW'
cyberrock_device_replyDaisyChainRW   =		environmentURL + 'api/device/replyDaisyChainRW'
cyberrock_device_checkRequestDaisyChainStatus =      environmentURL + 'api/device/checkRequestDaisyChainStatus'

cyberrock_device_requestHostDaisyChainAuthentication =		environmentURL + 'api/device/requestHostDaisyChainAuthentication'
cyberrock_device_checkRequestHostDaisyChainAuthenticationStatus =      environmentURL + 'api/device/checkRequestHostDaisyChainAuthenticationStatus'

cyberrock_device_requestHostSecureBootAttestation =		environmentURL + 'api/device/requestHostSecureBootAttestation'
cyberrock_device_checkHostSecureBootAttestationStatus =      environmentURL + 'api/device/checkHostSecureBootAttestationStatus'

cyberrock_device_requestDaisyChainHRW =      environmentURL + 'api/device/requestDaisyChainHRW'
cyberrock_device_checkRequestDaisyChainHRWStatus =      environmentURL + 'api/device/checkRequestDaisyChainHRWStatus'

cyberrock_device_requestSecureBootAttestationHRW =      environmentURL + 'api/device/requestSecureBootAttestationHRW'
cyberrock_device_checkRequestSecureBootAttestationHRWStatus =      environmentURL + 'api/device/checkRequestSecureBootAttestationHRWStatus'

cyberrock_device_mutualauth_requestcw =       environmentURL + 'api/device/requestMutualAuthCW'
cyberrock_device_mutualauth_replyrw =         environmentURL + 'api/device/replyMutualAuthRW'
cyberrock_device_mutualauth_checkstatus =     environmentURL + 'api/device/checkMutualAuthStatus'

cyberrock_device_hostmutualauth_request =          environmentURL + 'api/device/requestHostMutualAuth'
cyberrock_device_hostmutualauth_checkstatus =      environmentURL + 'api/device/checkHostMutualStatus'


tenantURL = environmentURL.replace('device-api', 'tenant-api')

cyberrock_tenant_login =   tenantURL + 'api/auth/tenantUserLogin'
cyberrock_tenant_claimtoken = tenantURL + 'api/tenantApi/claim-token'

sleeptime = 0.3

default_verbose = True
default_signature = False

#helper functions

def _parse_response(response, context=""):
	try:
		response.raise_for_status()
		return response.json()
	except requests.HTTPError as e:
		raise RuntimeError(f"HTTP {response.status_code} on {context}: {response.text}") from e
	except ValueError as e:
		raise RuntimeError(f"Invalid JSON on {context}: {response.text}") from e

#CyberRock calls
def do_device_login(cloudflaretokens, iotusername, iotpassword, verbose = default_verbose):

	if verbose: print("Logging in to CyberRock IoT portal")

	response = requests.post(cyberrock_device_login,
	 headers = cloudflaretokens,
	 data = {'username': iotusername, 'password': iotpassword},
	 )

	if verbose: print(response.status_code)

	logindata = _parse_response(response, "CyberRock login")
#    if verbose: print(logindata)

	accesstoken = (logindata['accessToken'])
	iotid = (logindata['deviceId'])

	return accesstoken, iotid

def do_device_tokenauth_requestcw(cloudflaretokens, accesstoken, TID, requestSignature = default_signature, verbose = default_verbose):

	if verbose: print("Retrieving CW from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {"requestSignedResponse": requestSignature,
			"TID": TID
			}

	response = requests.post(cyberrock_device_tokenauth_requestcw,
	 headers = data_auth, json = data_post,
	 )

	cwdata = _parse_response(response, "requestCW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(cwdata)

	CW = cwdata['CW']
	transactionid = cwdata['transactionId']

	return CW, transactionid

def do_device_tokenauth_replyrw(cloudflaretokens, accesstoken, TID, CW, RW, transactionid, requestSignature = default_signature, verbose = default_verbose):

	if verbose: print("Submitting RW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"requestSignedResponse": requestSignature,
		"TID": TID,
		"CW": CW,
		"RW": RW,
		"transactionId": transactionid
			}

	response = requests.post(cyberrock_device_tokenauth_replyrw,
	 headers = data_auth, json = data_post,
	 )

	rwdata = _parse_response(response, "replyRW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(rwdata)

	transactionid = rwdata['transactionId']

	return transactionid

def do_device_tokenauth_checkstatus(cloudflaretokens, accesstoken, transactionid, requestSignature = default_signature, verbose = default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_tokenauth_checkstatus,
		 headers = data_auth, params = params_post, json = data_post,
		 )

		responsedata = _parse_response(response, "Token Authentication Check Status")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid

def do_tenant_login(cloudflaretokens, tenantusername, tenantpassword, verbose = default_verbose):

	if verbose: print("Logging in to CyberRock Tenant portal")

	response = requests.post(cyberrock_tenant_login,
	 headers = cloudflaretokens,
	 data = {'email': tenantusername, 'password': tenantpassword},
	 )

	logindata = _parse_response(response, "Tenant login")

	if verbose: print(response.status_code)
	if verbose: print(logindata)

	tenantaccesstoken = (logindata['accessToken'])

	return tenantaccesstoken


def do_tenant_claimtoken(cloudflaretokens, tenantaccesstoken, claimid, verbose = default_verbose):

	if verbose: print("Claiming TID in CyberRock Tenant portal")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + tenantaccesstoken}

	response = requests.post(cyberrock_tenant_claimtoken,
	 headers = data_auth,
	 data = {'claimTokenId': claimid}
	 )

	responsedata = _parse_response(response, "Tenant Claim Token")
	result = (responsedata['result'])

	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return result

def do_device_priorityhostauth(cloudflaretokens, accesstoken, TID, HCW, HRW, verbose = default_verbose):

	if verbose: print("Submitting HCW,HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW
		}

	# if verbose: print(HCW)
	# if verbose: print(HRW)

	response = requests.post(cyberrock_device_priorityhostauth,
	headers = data_auth, json = data_post,
	)

	responsedata = _parse_response(response, "Priority Host Authentication")
	result = (responsedata['status'])

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return result


def do_device_hostauth_request(cloudflaretokens, accesstoken, TID, HCW, HRW, verbose=default_verbose):
	if verbose: print("Submitting HCW,HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW
	}

	# if verbose: print(HCW)
	# if verbose: print(HRW)

	response = requests.post(cyberrock_device_hostauth_request,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "Host Authentication Request")
	transactionid = responsedata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return transactionid


def do_device_hostauth_checkstatus(cloudflaretokens, accesstoken, transactionid, requestSignature=default_signature,
									verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_hostauth_checkstatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "Host Authentication CheckStatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid


def do_device_hostauthEK_request(cloudflaretokens, accesstoken, TID, HCW, HRW, verbose=default_verbose):
	if verbose: print("Submitting HCW,HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW
	}

	# if verbose: print(HCW)
	# if verbose: print(HRW)

	response = requests.post(cyberrock_device_hostauthEK_request,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_hostauthEK_request")
	transactionid = responsedata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return transactionid


def do_device_hostauthEK_checkstatus(cloudflaretokens, accesstoken, transactionid, requestSignature=default_signature,
									verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_hostauthEK_checkstatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "do_device_hostauthEK_checkstatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	ekresult = responsedata['EK']

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid, ekresult


def do_device_hostauthEK_request_rsa(cloudflaretokens, accesstoken, TID, HCW, HRW, recipient_public_key_pem, verbose=default_verbose):
	"""Host auth EK request with RSA public key for encrypted EK delivery."""
	if verbose: print("Submitting HCW,HRW to CyberRock (RSA encrypted EK)")

	pem_normalized = recipient_public_key_pem.replace('\r\n', '\n').strip()

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW,
		"recipientPublicKey": pem_normalized
	}

	response = requests.post(cyberrock_device_hostauthEK_request,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_hostauthEK_request_rsa")
	transactionid = responsedata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return transactionid


def do_device_hostauthEK_checkstatus_rsa(cloudflaretokens, accesstoken, transactionid, requestSignature=default_signature,
									verbose=default_verbose):
	"""Poll for host auth EK result (RSA variant). Returns encrypted EK."""
	if verbose: print("Retrieving encrypted EK result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_hostauthEK_checkstatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "do_device_hostauthEK_checkstatus_rsa")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if 'encryptedEK' in responsedata:
		encrypted_ek = responsedata['encryptedEK']
	elif 'EK' in responsedata:
		encrypted_ek = responsedata['EK']
	else:
		encrypted_ek = None

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid, encrypted_ek


# def do_device_requestHRWtransactionid(cloudflaretokens, accesstoken, TID, HCW, verbose = default_verbose):
#
#     if verbose: print("do_device_requestHRWtransactionid stub for backwards compatibility")
#
#     return None
#
# def do_device_requestHRW(cloudflaretokens, accesstoken, TID, HCW, transactionid, verbose = default_verbose):
#     # stub for backwards compatibility
#     return do_device_requestHRW(cloudflaretokens, accesstoken, TID, HCW, transactionid, verbose)

def do_device_requestHRW(cloudflaretokens, accesstoken, TID, HCW, verbose = default_verbose):

	if verbose: print("Submitting TID, HCW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW
		}

	response = requests.post(cyberrock_device_requestHRW,
	headers = data_auth, json = data_post,
	)

	tiddata = _parse_response(response, "do_device_requestHRW")
	transactionid = tiddata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(tiddata)

	return transactionid


def do_device_requestHRWstatus(cloudflaretokens, accesstoken, HRWtransactionID, verbose = default_verbose):

	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	result = 'NOT_READY'

	while ((result == 'NOT_READY') or (result == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_requestHRWstatus,
		headers = data_auth, params = {"transactionId": HRWtransactionID},
		)

		responsedata = _parse_response(response, "do_device_requestHRWstatus")
		result = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (result == 'GENERATED_HRW'):
		hrw = responsedata['HRW']
	else:
		hrw = ''

	return result, hrw


def do_device_tokenauthEK_requestcw(cloudflaretokens, accesstoken, TID, requestSignature = default_signature, verbose = default_verbose):

	if verbose: print("Retrieving CW from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
			"requestSignedResponse": requestSignature,
			"TID": TID
			}

	response = requests.post(cyberrock_device_tokenauthEK_requestcw,
	 headers = data_auth, json = data_post,
	 )

	cwdata = _parse_response(response, "do_device_tokenauthEK_requestcw")
	CW = cwdata['CW']
	transactionid = cwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(cwdata)

	return CW, transactionid


def do_device_tokenauthEK_requestcw_rsa(cloudflaretokens, accesstoken, TID, recipient_public_key_pem, requestSignature = default_signature, verbose = default_verbose):
	"""Request CW for EK authentication with RSA-2048 encrypted EK delivery.

	Same as do_device_tokenauthEK_requestcw but includes the recipient's RSA public key
	so the cloud will return the EK encrypted with that key (hybrid-crypto-js format).

	Args:
		recipient_public_key_pem: RSA-2048 public key in PEM format (string).
		    Sent as the full PEM string with literal \\n for line breaks.
	"""
	if verbose: print("Retrieving CW from CyberRock (RSA encrypted EK)")

	# Send PEM with \n as literal newline characters (not CRLF or escaped)
	pem_normalized = recipient_public_key_pem.replace('\r\n', '\n').strip()

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
			"requestSignedResponse": requestSignature,
			"recipientPublicKey": pem_normalized,
			"TID": TID
			}

	response = requests.post(cyberrock_device_tokenauthEK_requestcw,
	 headers = data_auth, json = data_post,
	 )

	cwdata = _parse_response(response, "do_device_tokenauthEK_requestcw_rsa")
	CW = cwdata['CW']
	transactionid = cwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(cwdata)

	return CW, transactionid

def do_device_tokenauthEK_replyrw(cloudflaretokens, accesstoken, TID, CW, RW, transactionid, requestSignature = default_signature, verbose = default_verbose):

	if verbose: print("Submitting RW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"requestSignedResponse": requestSignature,
		"TID": TID,
		"CW": CW,
		"RW": RW,
		"transactionId": transactionid
			}

	response = requests.post(cyberrock_device_tokenauthEK_replyrw,
	 headers = data_auth, json = data_post,
	 )

	rwdata = _parse_response(response, "do_device_tokenauthEK_replyrw")
	transactionid = rwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(rwdata)

	return transactionid

def do_device_tokenauthEK_checkstatus(cloudflaretokens, accesstoken, transactionid, requestSignature = default_signature, verbose = default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	params_post = {"transactionId": transactionid}

	data_post = {"requestSignedResponse": requestSignature}


	authenticationresult = 'NOT_READY'

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_tokenauthEK_checkstatus,
		 headers = data_auth, params = params_post, json = data_post,
		 )

		responsedata = _parse_response(response, "do_device_tokenauthEK_checkstatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if 'EK' in responsedata:
		ekresult = responsedata['EK']
	else:
		ekresult = None

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid, ekresult


def do_device_tokenauthEK_checkstatus_rsa(cloudflaretokens, accesstoken, transactionid, requestSignature = default_signature, verbose = default_verbose):
	"""Poll for EK authentication result (RSA variant).

	Same as do_device_tokenauthEK_checkstatus but expects the EK to be returned
	in encrypted form (hybrid-crypto-js format) because the RSA public key was
	submitted in the requestcw call.

	Returns:
		(authenticationresult, claimid, encrypted_ek)
		where encrypted_ek is the hybrid-encrypted EK JSON string.
	"""
	if verbose: print("Retrieving encrypted EK result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	params_post = {"transactionId": transactionid}

	data_post = {"requestSignedResponse": requestSignature}

	authenticationresult = 'NOT_READY'

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_tokenauthEK_checkstatus,
		 headers = data_auth, params = params_post, json = data_post,
		 )

		responsedata = _parse_response(response, "do_device_tokenauthEK_checkstatus_rsa")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if 'encryptedEK' in responsedata:
		encrypted_ek = responsedata['encryptedEK']
	elif 'EK' in responsedata:
		# EK field contains the hybrid-encrypted JSON string when recipientPublicKey was provided
		encrypted_ek = responsedata['EK']
	else:
		encrypted_ek = None

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid, encrypted_ek


def do_device_EKpriorityhostauth(cloudflaretokens, accesstoken, TID, HCW, HRW, verbose = default_verbose):
	if verbose: print("Submitting HCW,HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW
	}

	# if verbose: print(HCW)
	# if verbose: print(HRW)

	response = requests.post(cyberrock_device_EKpriorityhostauth,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_EKpriorityhostauth")
	result = (responsedata['status'])
	ekresult = responsedata['EK']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return result, ekresult


def do_device_EKpriorityhostauth_rsa(cloudflaretokens, accesstoken, TID, HCW, HRW, recipient_public_key_pem, verbose = default_verbose):
	"""Synchronous host auth + EK with RSA public key for encrypted EK delivery."""
	if verbose: print("Submitting HCW,HRW to CyberRock (RSA encrypted EK, priority)")

	pem_normalized = recipient_public_key_pem.replace('\r\n', '\n').strip()

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW,
		"recipientPublicKey": pem_normalized
	}

	response = requests.post(cyberrock_device_EKpriorityhostauth,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_EKpriorityhostauth_rsa")
	result = (responsedata['status'])

	if 'encryptedEK' in responsedata:
		encrypted_ek = responsedata['encryptedEK']
	elif 'EK' in responsedata:
		encrypted_ek = responsedata['EK']
	else:
		encrypted_ek = None

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return result, encrypted_ek


# def do_device_EKrequestHRWtransactionid(cloudflaretokens, accesstoken, TID, HCW, verbose = default_verbose):
#
#     if verbose: print("do_device_EKrequestHRWtransactionid stub for backwards compatibility")
#     return None
#
# def do_device_EKrequestHRW(cloudflaretokens, accesstoken, TID, HCW, transactionid, verbose = default_verbose):
#
#     if verbose: print("do_device_EKrequestHRWtransactionid stub for backwards compatibility")
#     return do_device_EKrequestHRW(cloudflaretokens, accesstoken, TID, HCW, transactionid, verbose)


def do_device_EKrequestHRW(cloudflaretokens, accesstoken, TID, HCW, verbose = default_verbose):
	if verbose: print("Submitting TID, HCW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW
	}

	response = requests.post(cyberrock_device_EKrequestHRW,
							 headers = data_auth, json = data_post,
							 )

	tiddata = _parse_response(response, "do_device_EKrequestHRW")
	transactionid = tiddata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(tiddata)

	return transactionid


def do_device_EKrequestHRWstatus(cloudflaretokens, accesstoken, HRWtransactionID, verbose = default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	result = 'NOT_READY'

	while ((result == 'NOT_READY') or (result == 'PROCESSING')):
		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_EKrequestHRWstatus,
								headers = data_auth, params={"transactionId": HRWtransactionID},
								)

		responsedata = _parse_response(response, "do_device_EKrequestHRWstatus")
		result = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (result == 'GENERATED_HRW'):
		hrw = responsedata['HRW']
		ekresult = responsedata['EK']
	else:
		hrw = ''
		ekresult = ''

	return result, hrw, ekresult


def do_device_EKrequestHRW_rsa(cloudflaretokens, accesstoken, TID, HCW, recipient_public_key_pem, verbose = default_verbose):
	"""Request HRW + EK with RSA public key for encrypted EK delivery."""
	if verbose: print("Submitting TID, HCW to CyberRock (RSA encrypted EK)")

	pem_normalized = recipient_public_key_pem.replace('\r\n', '\n').strip()

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"recipientPublicKey": pem_normalized
	}

	response = requests.post(cyberrock_device_EKrequestHRW,
							 headers = data_auth, json = data_post,
							 )

	tiddata = _parse_response(response, "do_device_EKrequestHRW_rsa")
	transactionid = tiddata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(tiddata)

	return transactionid


def do_device_EKrequestHRWstatus_rsa(cloudflaretokens, accesstoken, HRWtransactionID, verbose = default_verbose):
	"""Poll for HRW + encrypted EK result (RSA variant)."""
	if verbose: print("Retrieving encrypted EK HRW result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	result = 'NOT_READY'

	while ((result == 'NOT_READY') or (result == 'PROCESSING')):
		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_EKrequestHRWstatus,
								headers = data_auth, params={"transactionId": HRWtransactionID},
								)

		responsedata = _parse_response(response, "do_device_EKrequestHRWstatus_rsa")
		result = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (result == 'GENERATED_HRW'):
		hrw = responsedata['HRW']
		if 'encryptedEK' in responsedata:
			encrypted_ek = responsedata['encryptedEK']
		elif 'EK' in responsedata:
			encrypted_ek = responsedata['EK']
		else:
			encrypted_ek = None
	else:
		hrw = ''
		encrypted_ek = None

	return result, hrw, encrypted_ek


def do_device_priorityrequestHRW(cloudflaretokens, accesstoken, TID, HCW, verbose = default_verbose):
	if verbose: print("Submitting HCW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW
	}

	# if verbose: print(HCW)

	response = requests.post(cyberrock_device_priorityrequestHRW,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_priorityrequestHRW")
	result = (responsedata['status'])
	hrw = responsedata['HRW']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return result, hrw


def do_device_EKpriorityrequestHRW(cloudflaretokens, accesstoken, TID, HCW, verbose = default_verbose):
	if verbose: print("Submitting HCW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW
	}

	# if verbose: print(HCW)

	response = requests.post(cyberrock_device_EKpriorityrequestHRW,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_EKpriorityrequestHRW")
	result = (responsedata['status'])
	hrw = responsedata['HRW']
	ekresult = responsedata['EK']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)


	return result, hrw, ekresult


def do_device_EKpriorityrequestHRW_rsa(cloudflaretokens, accesstoken, TID, HCW, recipient_public_key_pem, verbose = default_verbose):
	"""Synchronous HRW + EK with RSA public key for encrypted EK delivery."""
	if verbose: print("Submitting HCW to CyberRock (RSA encrypted EK, priority)")

	pem_normalized = recipient_public_key_pem.replace('\r\n', '\n').strip()

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"recipientPublicKey": pem_normalized
	}

	response = requests.post(cyberrock_device_EKpriorityrequestHRW,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "do_device_EKpriorityrequestHRW_rsa")
	result = (responsedata['status'])
	hrw = responsedata['HRW']

	if 'encryptedEK' in responsedata:
		encrypted_ek = responsedata['encryptedEK']
	elif 'EK' in responsedata:
		encrypted_ek = responsedata['EK']
	else:
		encrypted_ek = None

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return result, hrw, encrypted_ek


def do_device_requestSecureBootAttestationCW(cloudflaretokens, accesstoken, l_TID, l_data, requestSignature, verbose = default_verbose):

	if verbose: print("Retrieving CW from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data)

	chaindata = []

	for i in range(len(l_TID)):
		chainblock = {"sequence": i+1, "TID": l_TID[i], "data": l_data[i]}
		chaindata.append(chainblock)

	data_post = {"requestSignedResponse": requestSignature,
				 "chain": chaindata
			 }

	response = requests.post(cyberrock_device_requestSecureBootAttestationCW,
	 headers = data_auth, json = data_post,
	 )

	cwdata = _parse_response(response, "do_device_requestSecureBootAttestationCW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(cwdata)

	BootCW = cwdata['BootCW']
	transactionid = cwdata['transactionId']

	return BootCW, transactionid

def do_device_replySecureBootAttestationRW(cloudflaretokens, accesstoken, l_TID, l_data, CW, HRW, transactionid, requestSignature, verbose = default_verbose):

	if verbose: print("Submitting RW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data)

	chaindata = []

	for i in range(len(l_TID)):
		chainblock = {"sequence": i+1, "TID": l_TID[i], "data": l_data[i]}
		chaindata.append(chainblock)

	data_post = {
		"requestSignedResponse": requestSignature,
		"BootCW": CW,
		"chain": chaindata,
		"HRW": HRW,
		"transactionId": transactionid
			}

	response = requests.post(cyberrock_device_replySecureBootAttestationRW,
	 headers = data_auth, json = data_post,
	 )

	rwdata = _parse_response(response, "do_device_replySecureBootAttestationRW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(rwdata)

	transactionid = rwdata['transactionId']

	return transactionid

def do_device_checkRequestSecureBootAttestationStatus(cloudflaretokens, accesstoken, transactionid, requestSignature, verbose = default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_checkRequestSecureBootAttestationStatus,
		 headers = data_auth, params = params_post, json = data_post,
		 )

		responsedata = _parse_response(response, "do_device_checkRequestSecureBootAttestationStatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, claimid


def do_device_requestDaisyChainCW(cloudflaretokens, accesstoken, l_TID, l_data, requestSignature, verbose = default_verbose):

	if verbose: print("Retrieving CW from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data) + 1

	chaindata = []

	chainblock = {"sequence": 1, "TID": l_TID[0]}
	chaindata.append(chainblock)
	for i in range(1,len(l_TID)):
		chainblock = {"sequence": i+1, "TID": l_TID[i], "data": l_data[i-1]}
		chaindata.append(chainblock)

	data_post = {"requestSignedResponse": requestSignature,
				 "chain": chaindata
			 }

	response = requests.post(cyberrock_device_requestDaisyChainCW,
	 headers = data_auth, json = data_post,
	 )

	cwdata = _parse_response(response, "do_device_requestDaisyChainCW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(cwdata)

	ChainCW = cwdata['ChainCW']
	transactionid = cwdata['transactionId']

	return ChainCW, transactionid

def do_device_replyDaisyChainRW(cloudflaretokens, accesstoken, l_TID, l_data, CW, HRW, transactionid, requestSignature, verbose = default_verbose):

	if verbose: print("Submitting RW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data) + 1

	chaindata = []

	chainblock = {"sequence": 1, "TID": l_TID[0]}
	chaindata.append(chainblock)
	for i in range(1,len(l_TID)):
		chainblock = {"sequence": i+1, "TID": l_TID[i], "data": l_data[i-1]}
		chaindata.append(chainblock)

	data_post = {
		"requestSignedResponse": requestSignature,
		"ChainCW": CW,
		"chain": chaindata,
		"HRW": HRW,
		"transactionId": transactionid
			}

	response = requests.post(cyberrock_device_replyDaisyChainRW,
	 headers = data_auth, json = data_post,
	 )

	rwdata = _parse_response(response, "do_device_replyDaisyChainRW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(rwdata)

	transactionid = rwdata['transactionId']

	return transactionid

def do_device_checkRequestDaisyChainStatus(cloudflaretokens, accesstoken, transactionid, requestSignature, verbose = default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_checkRequestDaisyChainStatus,
		 headers = data_auth, params = params_post, json = data_post,
		 )

		responsedata = _parse_response(response, "do_device_checkRequestDaisyChainStatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	return authenticationresult

# /api/device/requestHostDaisyChainAuthentication
# /api/device/checkRequestHostDaisyChainAuthenticationStatus

def do_device_HostDaisyChainAuthentication(cloudflaretokens, accesstoken, l_TID, l_data, HCW, HRW, requestSignature,
								verbose=default_verbose):
	if verbose: print("Submitting ChainCW, HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data) + 1

	chaindata = []

	chainblock = {"sequence": 1, "TID": l_TID[0]}
	chaindata.append(chainblock)
	for i in range(1, len(l_TID)):
		chainblock = {"sequence": i + 1, "TID": l_TID[i], "data": l_data[i - 1]}
		chaindata.append(chainblock)

	data_post = {
		"requestSignedResponse": requestSignature,
		"ChainCW": HCW,
		"chain": chaindata,
		"HRW": HRW
	}

	response = requests.post(cyberrock_device_requestHostDaisyChainAuthentication,
							 headers = data_auth, json = data_post,
							 )

	hcwdata = _parse_response(response, "do_device_HostDaisyChainAuthentication")
	transactionid = hcwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(hcwdata)

	return transactionid


def do_device_checkRequestHostDaisyChainAuthenticationStatus(cloudflaretokens, accesstoken, transactionid, requestSignature,
										   verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_checkRequestHostDaisyChainAuthenticationStatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "do_device_checkRequestHostDaisyChainAuthenticationStatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	return authenticationresult

# /api/device/requestHostSecureBootAttestation
# /api/device/checkHostSecureBootAttestationStatus


def do_device_requestHostSecureBootAttestation(cloudflaretokens, accesstoken, l_TID, l_data, HCW, HRW, requestSignature,
								verbose=default_verbose):
	if verbose: print("Submitting BootCW, HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data) 

	chaindata = []

	for i in range(0, len(l_TID)):
		chainblock = {"sequence": i + 1, "TID": l_TID[i], "data": l_data[i]}
		chaindata.append(chainblock)

	data_post = {
		"requestSignedResponse": requestSignature,
		"BootCW": HCW,
		"chain": chaindata,
		"HRW": HRW
	}

	if verbose: print(data_post)


	response = requests.post(cyberrock_device_requestHostSecureBootAttestation,
							 headers = data_auth, json = data_post,
							 )

	hcwdata = _parse_response(response, "do_device_requestHostSecureBootAttestation")
	transactionid = hcwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(hcwdata)

	return transactionid


def do_device_checkHostSecureBootAttestationStatus(cloudflaretokens, accesstoken, transactionid, requestSignature,
										   verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_checkHostSecureBootAttestationStatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "do_device_checkHostSecureBootAttestationStatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	return authenticationresult

# /api/device/requestDaisyChainHRW
# /api/device/checkRequestDaisyChainHRWStatus


def do_device_requestDaisyChainHRW(cloudflaretokens, accesstoken, l_TID, l_data, HCW, requestSignature,
								verbose=default_verbose):
	if verbose: print("Submitting ChainCW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data) + 1

	chaindata = []

	chainblock = {"sequence": 1, "TID": l_TID[0]}
	chaindata.append(chainblock)
	for i in range(1, len(l_TID)):
		chainblock = {"sequence": i + 1, "TID": l_TID[i], "data": l_data[i - 1]}
		chaindata.append(chainblock)

	data_post = {
		"requestSignedResponse": requestSignature,
		"ChainCW": HCW,
		"chain": chaindata
	}

	response = requests.post(cyberrock_device_requestDaisyChainHRW,
							 headers = data_auth, json = data_post,
							 )

	hcwdata = _parse_response(response, "do_device_requestDaisyChainHRW")
	transactionid = hcwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(hcwdata)

	return transactionid


def do_device_checkRequestDaisyChainHRWStatus(cloudflaretokens, accesstoken, transactionid, requestSignature,
										   verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_checkRequestDaisyChainHRWStatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "do_device_checkRequestDaisyChainHRWStatus")
		
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	hrw = responsedata['HRW']

	return hrw

def do_device_requestSecureBootAttestationHRW(cloudflaretokens, accesstoken, l_TID, l_data, HCW, requestSignature,
								verbose=default_verbose):
	if verbose: print("Submitting ChainCW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	assert len(l_TID) == len(l_data)

	chaindata = []

	for i in range(0, len(l_TID)):
		chainblock = {"sequence": i + 1, "TID": l_TID[i], "data": l_data[i]}
		chaindata.append(chainblock)

	data_post = {
		"requestSignedResponse": requestSignature,
		"BootCW": HCW,
		"chain": chaindata
	}

	response = requests.post(cyberrock_device_requestSecureBootAttestationHRW,
							 headers = data_auth, json = data_post,
							 )

	hcwdata = _parse_response(response, "do_device_requestSecureBootAttestationHRW")
	transactionid = hcwdata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(hcwdata)

	return transactionid


def do_device_checkRequestSecureBootAttestationHRWStatus(cloudflaretokens, accesstoken, transactionid, requestSignature,
										   verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_checkRequestSecureBootAttestationHRWStatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "do_device_checkRequestSecureBootAttestationHRWStatus")
		authenticationresult = responsedata['status']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	hrw = responsedata['HRW']

	return hrw


def do_device_mutualauth_requestcw(cloudflaretokens, accesstoken, TID, requestSignature = default_signature, verbose = default_verbose):

	if verbose: print("Retrieving CW from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {"requestSignedResponse": requestSignature,
			"TID": TID
			}

	response = requests.post(cyberrock_device_mutualauth_requestcw,
	 headers = data_auth, json = data_post,
	 )

	cwdata = _parse_response(response, "requestCW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(cwdata)

	CW = cwdata['CW']
	transactionid = cwdata['transactionId']

	return CW, transactionid

def do_device_mutualauth_replyrw(cloudflaretokens, accesstoken, TID, CW, RW, transactionid, requestSignature = default_signature, verbose = default_verbose):

	if verbose: print("Submitting RW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"requestSignedResponse": requestSignature,
		"TID": TID,
		"CW": CW,
		"RW": RW,
		"transactionId": transactionid
			}

	response = requests.post(cyberrock_device_mutualauth_replyrw,
	 headers = data_auth, json = data_post,
	 )

	rwdata = _parse_response(response, "replyRW")

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(rwdata)

	transactionid = rwdata['transactionId']

	return transactionid

def do_device_mutualauth_checkstatus(cloudflaretokens, accesstoken, transactionid, requestSignature = default_signature, verbose = default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_mutualauth_checkstatus,
		 headers = data_auth, params = params_post, json = data_post,
		 )

		responsedata = _parse_response(response, "Token Authentication Check Status")
		authenticationresult = responsedata['status']
		hrw2 = responsedata['HRW2']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, hrw2, claimid


def do_device_hostmutualauth_request(cloudflaretokens, accesstoken, TID, HCW, HRW, verbose=default_verbose):
	if verbose: print("Submitting HCW,HRW to CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	data_post = {
		"TID": TID,
		"HCW": HCW,
		"HRW": HRW
	}

	# if verbose: print(HCW)
	# if verbose: print(HRW)

	response = requests.post(cyberrock_device_hostmutualauth_request,
							 headers = data_auth, json = data_post,
							 )

	responsedata = _parse_response(response, "Host Authentication Request")
	transactionid = responsedata['transactionId']

	if verbose: print(response.url)
	if verbose: print(response.status_code)
	if verbose: print(responsedata)

	return transactionid


def do_device_hostmutualauth_checkstatus(cloudflaretokens, accesstoken, transactionid, requestSignature=default_signature,
									verbose=default_verbose):
	if verbose: print("Retrieving result from CyberRock")

	data_auth = cloudflaretokens | {'Authorization': 'Bearer ' + accesstoken}

	authenticationresult = 'NOT_READY'

	params_post = {"transactionId": transactionid}

	data_post = {
		"requestSignedResponse": requestSignature}

	while ((authenticationresult == 'NOT_READY') or (authenticationresult == 'PROCESSING')):

		time.sleep(sleeptime)

		response = requests.get(cyberrock_device_hostmutualauth_checkstatus,
								headers = data_auth, params=params_post, json = data_post,
								)

		responsedata = _parse_response(response, "Host Authentication CheckStatus")
		authenticationresult = responsedata['status']
		hrw2 = responsedata['HRW2']

		if verbose: print(response.url)
		if verbose: print(response.status_code)
		if verbose: print(responsedata)

	if (authenticationresult == 'CLAIM_TOKEN'):
		claimid = responsedata['claimTokenId']
	else:
		claimid = ''

	return authenticationresult, hrw2, claimid
