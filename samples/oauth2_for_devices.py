# -*- coding: utf-8 -*-

# See:  https://developers.google.com/accounts/docs/OAuth2ForDevices

import httplib2
from oauth2client.client import OAuth2WebServerFlow
from googleapiclient.discovery import build

CLIENT_ID = "some+client+id"
CLIENT_SECRET = "some+client+secret"
SCOPES = ("https://www.googleapis.com/auth/youtube",)

flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, " ".join(SCOPES))

# Step 1: get user code and verification URL
# https://developers.google.com/accounts/docs/OAuth2ForDevices#obtainingacode
flow_info = flow.step1_get_device_and_user_codes()
print "Enter the following code at %s: %s" % (flow_info.verification_url,
                                              flow_info.user_code)
print "Then press Enter."
raw_input()

# Step 2: get credentials
# https://developers.google.com/accounts/docs/OAuth2ForDevices#obtainingatoken
credentials = flow.step2_exchange(device_flow_info=flow_info)
print "Access token:", credentials.access_token
print "Refresh token:", credentials.refresh_token

# Get YouTube service
# https://developers.google.com/accounts/docs/OAuth2ForDevices#callinganapi
youtube = build("youtube", "v3", http=credentials.authorize(httplib2.Http()))
