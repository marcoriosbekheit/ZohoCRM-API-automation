# google api packages
from __future__ import print_function

import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from datetime import date

# from curses.ascii import isalnum
import json
import os
import datetime
import requests
from pprint import pprint
from cryptography.fernet import Fernet
import io


def keyGen():
    # key generation
    key = Fernet.generate_key()
    print(key)

    # # string the key in a file
    # with open('filekey.key', 'wb') as filekey:
    #     filekey.write(key)
    
    # # opening the key
    # with open('filekey.key', 'rb') as filekey:
    #     key = filekey.read()


def encryptJSONFile(key, fileName):
    # using the generated key
    fernet = Fernet(key)

    # opening the original file to encrypt
    with open(fileName, 'rb') as file:
        original = file.read()
        
    # encrypting the file
    encrypted = fernet.encrypt(original)

    # opening the file in write mode and
    # writing the encrypted data
    with open(fileName, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)


def decryptJSONFile(key, fileName):
    # using the key
    fernet = Fernet(key)

    # opening the encrypted file
    with open(fileName, 'rb') as enc_file:
        encrypted = enc_file.read()

    # decrypting the file
    decrypted = fernet.decrypt(encrypted)
    # import io
    f = io.BytesIO(decrypted)
    json_object = json.load(f)
    return json_object


def create_folder(service, folderName):
    """ Create a folder and prints the folder ID
    Returns : Folder Id

    Load pre-authorized user credentials from the environment.
    TODO(developer) - See https://developers.google.com/identity
    for guides on implementing OAuth2 for the application.
    """
    # creds, _ = google.auth.default()

    try:
        # create drive api client
        # service = build('drive', 'v3', credentials=creds)
        file_metadata = {
            'name': folderName,
            'mimeType': 'application/vnd.google-apps.folder'
        }

        # pylint: disable=maybe-no-member
        file = service.files().create(body=file_metadata, fields='id'
                                      ).execute()
        print(F'Folder has created with ID: "{file.get("id")}".')

    except HttpError as error:
        print(F'An error occurred: {error}')
        file = None

    return file.get('id')


def upload_to_folder(service, real_folder_id):
    """Upload a file to the specified folder and prints file ID, folder ID
    Args: Id of the folder
    Returns: ID of the file uploaded

    Load pre-authorized user credentials from the environment.
    TODO(developer) - See https://developers.google.com/identity
    for guides on implementing OAuth2 for the application.
    """
    # creds, _ = google.auth.default()

    try:
        # create drive api client
        # service = build('drive', 'v3', credentials=creds)

        folder_id = real_folder_id
        file_metadata = {
            'name': 'template.xlsx',
            'parents': [folder_id]
        }
        media = MediaFileUpload('template.xlsx',
                                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', resumable=True)
        # pylint: disable=maybe-no-member
        file = service.files().create(body=file_metadata, media_body=media,
                                      fields='id').execute()
        print(F'File with ID: "{file.get("id")}" has added to the folder with '
              F'ID "{real_folder_id}".')

    except HttpError as error:
        print(F'An error occurred: {error}')
        file = None

    return file.get('id')


def batch_update_values(creds, spreadsheet_id, data):
    # creds, _ = google.auth.default()
    # pylint: disable=maybe-no-member
    # spreadsheet_id = 'id1'
    # spreadsheet_id = 'id2'
    # spreadsheet_id = 'id3' # Template File
    try:
        service = build('sheets', 'v4', credentials=creds, static_discovery=False)
        # if zohoData["Billing_Street"].replace(" ", "") != "":
        #     streetAddress = zohoData["Billing_Street"] + ', ' + zohoData["Billing_City"] + ', ' + zohoData["Billing_State"]
        # else:
        #     streetAddress = ""
        body = {
            'valueInputOption': 'USER_ENTERED',
            'data': data
        }
        result = service.spreadsheets().values().batchUpdate(
            spreadsheetId=spreadsheet_id, body=body).execute()
        print(f"{(result.get('totalUpdatedCells'))} cells updated.")
        return result
    except HttpError as error:
        print(f"An error occurred: {error}")
        return error


def listDriveFiles(service):
    # can be used to check what the current API scope has access to
    # Call the Drive v3 API
    results = service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
        return
    print('Files:')
    for item in items:
        print(u'{0} ({1})'.format(item['name'], item['id']))


def googleAPImain(data, key, accountName):

    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    # 'https://www.googleapis.com/auth/drive.file'
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
    
    fileName = 'token.json'
    if os.path.exists(fileName):
        # creds = Credentials.from_authorized_user_file(fileName, SCOPES)
        credData = decryptJSONFile(key, fileName)
        creds = Credentials.from_authorized_user_info(credData, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            credData = decryptJSONFile(key, 'credentials.json')
            flow = InstalledAppFlow.from_client_config(credData, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
        encryptJSONFile(key, 'token.json')

    # Run Batch update
    
    try:
        service = build('drive', 'v3', credentials=creds, static_discovery=False)
        
        # # Create Folder on 1st start TODO
        configFileName = 'config.json'
        if os.path.exists(configFileName): # if file exists, not first run
            with open(configFileName, 'r') as openfile:
                # Reading from json file
                configData = json.load(openfile)
                folderID = configData['folderID']
        else:
            folderID = create_folder(service, "ZohoCRM_SOF")
            print("Folder ID:", folderID)
            dictionary = {
                'folderID': folderID,
                'firstRun': False
            }
            with open(configFileName, "w") as outfile:
                json.dump(dictionary, outfile)

        

        
        
        # # Upload template.xlsx to parent folder on 1st start TODO

        # Copy Template File
        newFileName = accountName + ' ' + str(date.today())
        # parentFolderID = 'FolderID'
        parentFolderID = folderID
        fileToCopyID = 'ID' # template file
        newfile = {'name': newFileName, 'parents' : [ parentFolderID]}
        copiedFileID = service.files().copy(fileId=fileToCopyID, body=newfile).execute()
        # print('copiedFileID:', copiedFileID['id'])
        print("New File created:", newFileName)

        # use copiedFileID to change expected values
        batch_update_values(creds, copiedFileID['id'], data=data)

        # listDriveFiles(service)
    except HttpError as error:
        # TODO(developer) - Handle errors from drive API.
        print(f'An error occurred: {error}')



# documentation: https://www.zoho.com/crm/developer/docs/api/v3/access-refresh.html
# https://api-console.zoho.com
# 1. go to zoho api console
# 2. select self client
# 3. go to generate code
# 4. create scope, time expire duration then generate code
#--------------------
# scope to use
# ZohoCRM.modules.accounts.READ
# ZohoCRM.modules.contacts.READ
# ZohoSearch.securesearch.READ
# ZohoCRM.modules.accounts.READ, ZohoCRM.modules.contacts.READ, ZohoSearch.securesearch.READ
def getRefreshToken():
    """ Runs once at 1st setup of zohocrm API """
    '''
        # documentation: https://www.zoho.com/crm/developer/docs/api/v3/access-refresh.html
        # https://api-console.zoho.com
        # 1. go to zoho api console
        # 2. select self client
        # 3. go to generate code
        # 4. create scope, time expire duration then generate code
        #--------------------
        # scope to use
        # ZohoCRM.modules.accounts.READ
        # ZohoCRM.modules.contacts.READ
        # ZohoSearch.securesearch.READ
    '''
    code = "something"
    clientID = "ID"
    clientSecret = "secret"
    tokenGenURL = "https://accounts.zoho.com/oauth/v2/token"



    params = {
        "grant_type": "authorization_code",
        "client_id": clientID,
        "client_secret": clientSecret,
        # "redirect_uri": "",
        "code": code
    }

    response = requests.post(tokenGenURL, data=params)
    dataOut = response.json()
    print(dataOut)
    print(response)
    print(response.json())    

def getAccessToken():
    """Runs once per hour"""
    # TODO store access token and time and check if time passed an hour


    dataFromFirstRun = {
        'access_token': 'token0',
        'refresh_token': 'token1', 
        'api_domain': 'https://www.zohoapis.com', 
        'token_type': 'Bearer', 
        'expires_in': 3600
    }
    clientID = "id"
    clientSecret = "secret"
    # refresh_token = dataFromFirstRun["refresh_token"]

    # create POST request URL from refresh token, clientID, clientSecret
    refreshTokenURL = "https://accounts.zoho.com/oauth/v2/token?refresh_token={}&client_id={}&client_secret={}&grant_type=refresh_token".format(
        dataFromFirstRun["refresh_token"], 
        clientID,
        clientSecret
        )
    
    # send POST request and get data
    response = requests.post(refreshTokenURL)
    dataOut = response.json()
    # print(dataOut)
    # print(response)
    # print(response.json())

    # get access token from data
    if response.status_code == 200:
        accessToken = dataOut['access_token']
        # print('Access Token:', accessToken)
        return accessToken
    else:
        print("error: refresh token request failed, code = {}".format(response.status_code))

def convertToJSON(dictionary):
    # Serializing json  
    json_object = json.dumps(dictionary, indent = 4) 
    print(json_object)

def showRelevantInfo(accessToken):
    pass
    headers = {
        'Authorization': 'Zoho-oauthtoken '+ accessToken,
    }
    # Search Accounts
    endLoop = False
    while(not endLoop):
        accountSearchInput = input("Search accounts that start with: ")
        # response = requests.get('https://www.zohoapis.com/crm/v3/Accounts/search?criteria=(Account_Name:starts_with:j)', headers=headers)
        response = requests.get('https://www.zohoapis.com/crm/v3/Accounts/search?criteria=(Account_Name:starts_with:'+accountSearchInput+')', headers=headers)
        if response.status_code == 204:
            print('No Accounts found matching the based on the search:', accountSearchInput)
        if response.status_code == 200:
            dataOut = response.json()
            endLoop = True
        # print(response)

    dataDict = dataOut["data"]
    num = len(dataDict)
    for i in range(0, num):
        print("=============", i+1, "=============")
        print("Account_Name:  ", dataDict[i]["Account_Name"])
        print("Account_Number:", dataDict[i]["Account_Number"])
        print("Created_Time:  ", dataDict[i]["Created_Time"])
        print("Billing_Street:", dataDict[i]["Billing_Street"])
        print("Billing_City:  ", dataDict[i]["Billing_City"])
        print("Billing_State: ", dataDict[i]["Billing_State"])
        print("Phone:         ", dataDict[i]["Phone"])
        
    
    
    # User Selection
    endLoop = False
    while(not endLoop):
        userInput = input("Choose a number: ")
        if userInput.isnumeric() and isinstance(int(userInput), int):
            userInput = int(userInput) - 1
            if userInput >= 0 and userInput <= num-1:
                endLoop = True
            else:
                print("Error: number cannot be less than 1 or greater than available options")
        else:
            print("Error: Input is not an integer number")

    # Store selected account data
    selectedAccountData = dataDict[i]

    # TODO Search Contacts based on selected account name from user selection
    accountName = dataDict[userInput]['Account_Name']
    print("account name = ", accountName)
    response = requests.get('https://www.zohoapis.com/crm/v3/Contacts/search?criteria=(Account_Name:equals:'+accountName+')', headers=headers)
    if response.status_code == 204:
        print('No Contacts found matching the selected account name,', accountName)
    if response.status_code == 200:
        dataOut = response.json()
        dataContacts = dataOut["data"]

    # TODO Print Matching contacts
    print("============= Matching Contacts =============")
    for i in range(0, len(dataContacts)):
        print("=============", i+1, "=============")
        print("Email:     ", dataContacts[i]["Email"])
        print("Full_Name: ", dataContacts[i]["Full_Name"])
        print("Phone:     ", dataContacts[i]["Phone"])
        print("Mobile:    ", dataContacts[i]["Mobile"])

    # TODO contact name with same name as account name is the main email
    mainEmail = None
    for i in range(0, len(dataContacts)):
        if accountName == dataContacts[i]["Full_Name"]:
            mainEmail = dataContacts[i]["Email"]
            dataContacts.pop(i)
            break
    if mainEmail == None:
        print("No main email found")
    
    # TODO account for billing city or state may be None as well
    if selectedAccountData["Billing_Street"] != None:
        if selectedAccountData["Billing_City"] != None or selectedAccountData["Billing_State"] != None:
            streetAddress = selectedAccountData["Billing_Street"] + ', ' + selectedAccountData["Billing_City"] + ', ' + selectedAccountData["Billing_State"]
        else:
            streetAddress = selectedAccountData["Billing_Street"]
    
    data = [
        { 
            'range': "'Client Info'!D3", # Client Name
            'values': [ [selectedAccountData["Account_Name"]] ] # [ [#1st row column cell values], [#2nd row column cell values], ...]
        },
        { 
            'range': "'Client Info'!D6", # Email
            'values': [ [mainEmail] ] # TODO (me) ask about D6 email
        },
        { 
            'range': "'Client Info'!F6", # Billing Address
            'values': [ [streetAddress] ] 
        },
        { 
            'range': "'Client Info'!B3", # Job Number
            'values': [ [selectedAccountData["Account_Number"]] ] 
        },
        { 
            'range': "'Client Info'!B6", # Phone Number
            'values': [ [selectedAccountData["Phone"]] ] 
        },
        # Additional ranges to update ...
    ]

    # TODO Append contacts into data array
    for i in range(0, len(dataContacts)):
        if i > 3-1: 
            break # because there is space for 3 contacts only
        temp = [
            {
                'range': "'Client Info'!B" + str(10+i),
                'values': [ [dataContacts[i]["Full_Name"]] ]
            },
            {
                'range': "'Client Info'!C" + str(10+i),
                'values': [ [dataContacts[i]["Email"]] ]
            },
            {
                'range': "'Client Info'!D" + str(10+i),
                'values': [ [dataContacts[i]["Phone"]] ]
            },
            {
                'range': "'Client Info'!E" + str(10+i),
                'values': [ [dataContacts[i]["Mobile"]] ]
            },
        ]
        data.append(temp)
    
    return data, accountName
    
    

def main():
    key = b'somekey'
    zohoTokenFileName = 'zoho.json'
    if os.path.exists(zohoTokenFileName):
        # open token file
        # with open(zohoTokenFileName, 'r') as openfile:
        #     # Reading from json file
        #     zohoTokenData = json.load(openfile)
        zohoTokenData = decryptJSONFile(key, zohoTokenFileName)

        # check time diff
        timeNow = datetime.datetime.now()
        timeOld = zohoTokenData['expires_in']
        format = "%Y-%m-%d %H:%M:%S.%f"
        timeOld = datetime.datetime.strptime(timeOld, format) # convert timeOld to datetime object
        diff = timeNow-timeOld

        # if 3600s passed, get new access token
        if diff.total_seconds() > 3600:
            accessToken = getAccessToken()
            temp = {
                'token': accessToken,
                'expires_in': str(datetime.datetime.now())
            }

            # write to file
            with open(zohoTokenFileName, "w") as outfile:
                json.dump(temp, outfile)
            # encrypt file
            encryptJSONFile(key, zohoTokenFileName)
        else: # else get token from existing file
            accessToken = zohoTokenData['token']
    else: # file does not exist, make a new one
        accessToken = getAccessToken()
        temp = {
            'token': accessToken,
            'expires_in': str(datetime.datetime.now())
        }
        with open(zohoTokenFileName, "w") as outfile:
            json.dump(temp, outfile)
        encryptJSONFile(key, zohoTokenFileName)
    # print(accessToken)


    data, accountName = showRelevantInfo(accessToken)
    googleAPImain(data, key, accountName)








if __name__ == '__main__':
    pass
    try:
        main()
    except Exception as e:
        print("Error:", e)
    input("Press Enter to exit")

