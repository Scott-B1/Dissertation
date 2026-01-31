__author__= 'Scott'


###------Imports------###
import os
import sqlite3
from contextlib import closing
from app import app
from flask import render_template, g, request
from qpylib import qpylib
import re
#import time
from timeit import default_timer as timer

###Setting database storage location to /store/ to prevent data from getting wiped by QRadar###
DATABASE = '/store/dsmstore.db'

###Setup app.config for the database 
app.config['DATABASE']=DATABASE;

###------Database setup functions------###

#Connects to the db and stores it in the 'g' object.
def get_db():
    g.db = sqlite3.connect( app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES )
    g.db.row_factory = sqlite3.Row #returns the rows as dictionary, useful later for grabbing column names directly
    return g.db
    
        
#Initialise the database, clears all data and creates it with new tables
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

#Function to insert initial-sample data on a table
def add_data():
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO sample (dsm_name, payload, ec, eid, lstime) VALUES('Check Point', 'LEEF:2.0|Check Point|VPN-1 & FireWall-1|1.0|Decrypt|cat=VPN-1 & FireWall-1	devTime=1546548320	srcPort=35354	action=Decrypt	ifdir=inbound	origin=192.168.122.96	dst=192.168.153.45	fw_subproduct=VPN-1	proto=6	rule=32	scheme:=IKE	service=8140	service_id=satellite_8140	src=10.148.64.188	vpn_feature_name=VPN', 'VPN-1 & FireWall-1', 'Decrypt', 'Jan 3, 2019, 8:45:20PM')")    
        db.execute("INSERT INTO sample (dsm_name, payload, ec, eid, lstime) VALUES('ESET Remote Administrator', '<14>1 2019-12-19T08:24:15.53Z 1.4.1.4 Server 5470 - - LEEF:1.0|ESET|RemoteAdministrator|7.0.471.0|Native user logout|cat=ESET RA Audit Event	sev=2	devTime=Dec 19 2019 08:24:15 GMT	devTimeFormat=MMM dd yyyy HH:mm:ss z	src=1.2.3.4	deviceName=1.4.1.4	domain=Native user	action=Logout	target=ib	detail=Logging out native user ib.	user=ib	result=Success', 'ESET RA Audit Event', 'Native user logout', 'Dec 19, 2019, 8:24:15 AM')")    
        db.execute("INSERT INTO sample (dsm_name, payload, ec, eid, lstime) VALUES('CrowdStrike Falcon Host', 'LEEF:1.0|CrowdStrike|FalconHost|1.0|Known Malware|cat=DocumentsAccessed	url=testUrl	docAccessedFilePath=\Device\HarddiskVolume1\Users\qradar.user1\Desktop	domain=testDomain	resource=testResource1	devTimeFormat=yyyy-MM-dd HH:mm:ss	devTime=2016-06-09 02:55:39	docAccessedFileName=out.doc	usrName=qradar.user1', 'DocumentsAccessed', 'Known Malware', 'Jun 9, 2016, 2:55:39 AM')")    
        db.execute("INSERT INTO sample (dsm_name, payload, ec, eid, lstime) VALUES('Microsoft Azure Platform', '{\"eventHubsAzureRecord\": {\"time\":\"2019-05-09T19:20:30.5302897Z\",\"resourceId\":\"/SUBSCRIPTIONS/3E5AF40F-33A2-4097-A4EA-A7FC051B645C/RESOURCEGROUPS/DEFAULT-ACTIVITYLOGALERTS/PROVIDERS/MICROSOFT.STREAMANALYTICS/STREAMINGJOBS/TESTJOB\",\"correlationId\":\"66abdf99-53a6-48d3-89b6-9865c0ad4005\",\"operationName\":\"Stop streaming job \test5average\",\"level\":\"Information\",\"resultType\":\"Completed\",\"resultSignature\":\"Completed\",\"resultDescription\":\"Stream Analytics job changed by user with [POST:RpJobManagement/StopStreamingJob].\",\"category\":\"Action\",\"location\":\"global\",\"properties\":{\"eventCategory\":\"Administrative\",\"eventName\":\"RpJobManagement\",\"operationId\":\"5e8e50c8-5e3e-4201-bb56-e36dd1d489c3\",\"eventProperties\":{\"StatusCode\":202,\"SubStatusCode\":0}}}}', 'microsoft.streamanalytics', 'stop streaming job', 'May 9, 2019, 7:20:30 PM')")    
        
        db.execute("INSERT INTO updatedsm (dsm_name, current_ver, latest_ver) VALUES('CiscoACS', '20181116032402', '20181116032402')")    
        db.execute("INSERT INTO updatedsm (dsm_name, current_ver, latest_ver) VALUES('CheckPoint', '20200929201223', '20200929201223')")    
        db.execute("INSERT INTO updatedsm (dsm_name, current_ver, latest_ver) VALUES('MicrosoftIIS', '20191123141102', '20200615203644')")  #  
        db.execute("INSERT INTO updatedsm (dsm_name, current_ver, latest_ver) VALUES('EMCVMWare', '20200810184447', '20200810184447')")    
        db.execute("INSERT INTO updatedsm (dsm_name, current_ver, latest_ver) VALUES('AkamaiKona', '20180727132309', '20200124200143')")   # 
        
        db.execute("INSERT INTO custom (dsm_name, ec_regex, eid_regex, payload) VALUES('TestDSM1', 'action=\S+', 'ifdir=\S+', 'LEEF:2.0|Check Point|VPN-1 & FireWall-1|1.0|Decrypt|cat=VPN-1 & FireWall-1	devTime=1546548320	srcPort=35354	action=Decrypt	ifdir=inbound	origin=192.168.122.96	dst=192.168.153.45	fw_subproduct=VPN-1	proto=6	rule=32	scheme:=IKE	service=8140	service_id=satellite_8140	src=10.148.64.188	vpn_feature_name=VPN')")
        
        db.commit()
        
#Only initialise the database if the database does not already exist as a file
def start_db():
    #qpylib.log(str(os.path.isfile(app.config['DATABASE'])))
    if not os.path.isfile(app.config['DATABASE']):
        init_db()
        add_data()
         

start_db() #After creating functions, ensure db has been created.
#init_db() 
#add_data()
 
#Lastly ensure that we open and close a database connection before and after each request with handlers
@app.before_request
def before_request():
    g.db = get_db()

@app.teardown_request
def teardown_request(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

###------Main Python Functions------###

#Function to search with regex, also times the regex search
def regex_search(regex, text):
    text_str = str(text) #ensures the input is a string
    regex_str = str(regex) #ensures the input is a string
    timeSec = 0 #initialise time count variable as 0
    if regex_str and regex_str.strip(): #ensures the input is not empty or just spaces
        if text_str and text_str.strip(): #ensures the input is not empty or just spaces

            timeAvg = 0 #initialise time average variable
            
            for i in range(20): #average over 20 iterations
                startTimer = timer() #start a timer
                regex_result = re.search(regex_str, text_str) #performs a regex search on the given inputs
                endTimer = (timer()- startTimer) #subtract timer difference
                timeAvg = timeAvg + endTimer #create an average time, important to do each time as system load and hardware can change, get an accurate figure each time.
   
            timeCount = timeAvg/20 #takes an average of 20 samples for display to the user
            #print "%.10f" % timeCount #to display to 10 digits
            timeSec = ("%.10f" % timeCount) #how to save as a variable
            
            if regex_result == None: #regex will return a None type object if the search did not give any results, handling errors for AttributeError: 'NoneType' object
                regex_result = "Error: Regex syntax did not return a value"
            else:
                regex_result = str(regex_result.group()) #return the regex text found by storing into regex_result
        else: 
            regex_result = "Error: Empty Text Input" #otherwise returns an error
    else:
        regex_result = "Error: Empty Regex Input" #otherwise returns an error
    
    return regex_result, timeSec #return the regex search and time taken

def regex_classification(result_string): #Defining a regex classification for a given input string

    classification = "none" #used for classifying the characters input
    int_counter1 = 0 #counter for integer character occurances
    string_counter1 = 0 #counter for string character occurances
    string_dot_counter = 0 #counter for dot character occurances
    string_special_counter = 0 #counter for special character occurances
    previous = "none" #variable for storing the previous identified character
    ip_block = "" #initalise variable for a potential IP number
    result_array = [] #initialise array for the result
    special_characters = "\"[@_!#$%^&*()<>?/\|},{~:;=+-'`|]" #special characters list
    
    for i in range(len(result_string.strip())): #length of field+its text
        for x in range(len(special_characters)):
            if result_string[i]==special_characters[x]: #check if the current character is a special character
                result_array.append("special") #could also append(special_character[x]) for complete accuracy
                previous = "string_special"
                string_special_counter +=1
                if classification == "int" or classification == "string_special_num" or classification == "string_num":
                    classification = "string_special_num"
                else:
                    classification = "string_special"
                break #doesn't need to continue checking the rest of the loop if we find a match
        if previous == "string_special": #if we have found the current character is a special character, then go to the next character
            previous = "none"
            continue
        if result_string[i].isdigit(): #if character is int #needs rewritten to check for number
            previous = "int"
            int_counter1 += 1
            result_array.append("int")
            ip_block += result_string[i]
            if classification == "int" or classification == "none":
                classification = "int"
            elif classification == "ip":
                if int(ip_block) > 255: #if a user inputs a number greater than 255 it is not an IP
                    classification = "string_special_num"
            else: #payload contains both letters and numbers so a generic string regex
                if classification == "string_special" or classification == "string_special_num":
                    classification = "string_special_num"
                else:
                    classification = "string_num"
                
        elif isinstance(result_string[i], str):
            if result_string[i] == ".": #if the current character is a dot, could be an IP
                result_array.append("dot")
                string_dot_counter += 1
                ip_block = "" #reset ip block on each dot
                if int_counter1 > 0  and previous == "int": #likely an IP being grabbed if only numbers and "." has been discovered
                    if string_dot_counter > 3 or int_counter1 > 12 or (classification != "int" and classification != "ip"): #IP only should have 4 sections (3 numbers each max) e.g. 255.255.255.255
                        classification = "string_special_num"
                    else:
                        classification = "ip" 
                else:
                    if classification == "int" or classification == "ip": #if there was consecutive dots input then allocate the correct classification
                        classification = "string_special_num"
                    else: #if previously only characters, allocate correct classification
                        classification = "string_special"
                previous = "string_dot"
            else:
                result_array.append("char")
                previous = "string"
                string_counter1 +=1 
                if (classification != "string_special" and classification != "string_special_num" and classification != "string_num"): #if none of the above, then just simple characters
                    if classification == "int":
                        classification = "string_num" 
                    else:
                        classification = "string"    
    
    if (string_dot_counter != 3 or previous != "int") and classification == "ip": #verifies that we are saving the correct classification for "ip"
        classification = "string_special_num" #failed the requirements to meet an IP, change the classification
    
    return classification, result_array

def regex_suggestion1(classification, result_string_length): #specify regex per scenario to ensure regex is more efficient than a generic string regex where possible
    #https://docs.python.org/2.7/faq/design.html#why-isn-t-there-a-switch-or-case-statement-in-python - python 2.66 does not have a switch statement built in, following will be if/else sequences
    regex_solution2 = "" #setup return variable
    if classification == "int":   #set regex for only numbers
        #below only searches based on the length of the string of digits
        regex_solution1 = "\\b[0-9]{" + str(result_string_length) + "}\\b"     #using escaped \b to ensure it is properly understood by python, using \b to ensure it only matches the correct digit field length, not the first set of digits it finds with at least that amount 
    
    elif classification == "string":   #set regex for only characters
        #below only searches based on the length of the string of characters
        regex_solution1 = "\\b[a-zA-Z]{" + str(result_string_length) + "}\\b" #using escaped \b to ensure it is properly understood by python, using \b to ensure it only matches the correct character field length, not the first character it finds with at least that amount
    
    elif classification == "string_num":  #set regex for both characters and numbers
        #below only searches based on the length of the string of characters and digits
        regex_solution1 = "\\b\\w{" + str(result_string_length) + "}\\b" #using escaped \b to ensure it is properly understood by python, using \b to ensure it only matches the correct character field length, not the first character it finds with at least that amount
    
    elif classification == "ip":  #set regex for ip template
        regex_solution1 = "([0-9]{1,3}\.){3}[0-9]{1,3}"  #not using \d as its slower https://stackoverflow.com/questions/16621738/why-is-the-d-in-my-regex-slower-than-0-9
    
    else: #else use generic regex that matches the length
        regex_solution1 = "\\b\\S{" + str(result_string_length) + "}\\b" #using escaped \b to ensure it is properly understood by python, using \b to ensure it only matches the correct character field length, not the first character it finds with at least that amount
    
    # https://docs.python.org/2.7/library/re.html#re-syntax for regex syntax
    
    return regex_solution1

def regex_suggestion2(result_array): #creating a custom regex solution here based on the result_array section calculated within regex_suggest method
    regex_solution2 = "\\b" #setup return variable
    next_identifier_counter = 1 #setup a counter variable
    for z in range(len(result_array)): #The overview of this is suggesting smart regex, if there is consecutive characters it wont repeat regex, but will provide good structure
        current_identifier = "\\S" #set a default \S identifier
        current_classification = "" #set a blank classification
        if next_identifier_counter > 1: #if the counter is greater than 1
            next_identifier_counter -= 1 #subtract it and skip this loop iteration
            continue
        
        if result_array[z] == "int": #if an integer, suggest [0-9]
            current_identifier = "[0-9]"
            current_classification = "int"
        elif result_array[z] == "char": #if an character, suggest \w
            current_identifier = "\\w"
            current_classification = "char"
        elif result_array[z] == "dot": #if an integer, suggest a literal dot
            current_identifier = "\."
            current_classification = "dot"
        
        while result_array[z] == current_classification: #a while loop to check the upcoming classifications if they are the same as the current
            if z+1 < len(result_array): #ensuring we do not reach an out of bounds error
                if result_array[z+1] == current_classification: #check if it is the same as the current classifcation
                    next_identifier_counter += 1 #increment counter if so
                z += 1 #increment local z for next check
            else:
                break #when we find a different classification, break out of the while loop
        
        regex_solution2 = regex_solution2 + current_identifier #add on the new regex piece
        if next_identifier_counter > 1: #if we found consecutive classifications, make it smart suggest not repeating identifiers.
            regex_solution2 = regex_solution2 + "{" + str(next_identifier_counter) + "}" #e.g. instead of \w\w\w it will display \w{3} 
    regex_solution2 += "\\b" #using \b to ensure it only matches the correct character field length, not the first character it finds with at least that amount
    return regex_solution2

#Function to suggest regex
def regex_suggest(payload, field): #Suggests up to 3 regex and the time taken to search, given a body of text
    field_str = str(field) #ensures the input is a string
    payload_str = str(payload) #ensures the input is a string
    regex_final = [] #setup return variables as arrays
    time_final = []  #setup return variables as arrays
    regex_result1 = "" 
    
    if payload_str and payload_str.strip(): #ensures the input is not empty or just spaces
        if field_str and field_str.strip(): #ensures the input is not empty or just spaces
            generic_regex = "\\s?\\S+" #Generic regex which expands until a space (also allowing for a single space to be at the start)
            regex = field_str + generic_regex #By default use regex which will just expand until the next space after the characters
            
            #above regex includes prerequisite "field_str" otherwise it will just find first set of characters from the input payload
            regex_final.append(regex) #use the sample as one of the returns
            regex_result1, timeCount1 = regex_search(regex, payload_str) #use the regex_search function to search for a default result using a generic regex grab 
            time_final.append(timeCount1) #use the sample time to match the initial sample return
            
            if "Error:" in str(regex_result1): #check if there is an error code in the variable
                regex_final = str(regex_result1) #if there was an error, pass through the error to return variable and exit the function
            else: #if no error, continue to suggest regex

                result_string = regex_result1.replace(field_str, '') #now remove field_str from result to prevent this from invalidating upcoming regex prediction
                result_string = result_string.strip() #removing any blank space
                result_string_length = len(result_string) #calculate the length for future calculations
                
                #create a generic classification and a specific log of each character in an array to create customised regex solutions
                classification, result_array = regex_classification(result_string)
                
                #creating a custom regex suggestion based on a generic classification
                regex_suggested1 = field_str + "\\s?" + regex_suggestion1(classification, result_string_length)
                
                #creating a custom regex solution here based on the specific characters in the result_array section and then doing a timing comparison between two options later
                regex_suggested2 = field_str + "\\s?" + regex_suggestion2(result_array) 
                
                if regex_suggested1 == regex_suggested2: #if this is the same regex identifier suggestion
                    regex_result3, timeCount3 = regex_search(regex_suggested2, payload_str) #use the regex_search function to only gather regex_suggested2 timings and result
                else: #gather both timings and results
                    regex_result2, timeCount2 = regex_search(regex_suggested1, payload_str) #use the regex_search function to gather regex_suggested1 timings and result
                    regex_result3, timeCount3 = regex_search(regex_suggested2, payload_str) #use the regex_search function to gather regex_suggested2 timings and result
                    if "Error:" in regex_result2:
                        regex_final.append(regex_result2) #if there was an error, pass through the error to return variable and exit the statement
                        time_final.append(0) #append a time of 0 to match the error return
                    else:
                        if regex_result2 == regex_result1: #check if the regex results are the same with the sample and therefore correct
                            regex_final.append(regex_suggested1) #add the successfully suggested regex   
                            time_final.append(timeCount2) #append the time to match the regex_suggested1 return
                
                if "Error:" in regex_result3: #as this will be carried out no matter what, saves code rather than including it twice in above if statement.
                    regex_final.append(regex_result3) #if there was an error, pass through the error to return variable and exit the statement
                    time_final.append(0) #append a time of 0 to match the error return
                else:
                    if regex_result3 == regex_result1: #check if the regex results are the same with the sample and therefore correct
                        regex_final.append(regex_suggested2) #add the successfully suggested regex         
                        time_final.append(timeCount3) #append the time to match the regex_suggested2 return
                

        else: 
            regex_final = "Error: Empty Field Input" #otherwise returns an error
            time_final = 0
    else:
        regex_final = "Error: Empty Payload Input" #otherwise returns an error
        time_final = 0
    
    return regex_final, time_final, regex_result1 #return the regex and times as array, will include the initial sample regex + time in first position, then other suggestions after (if applicable)


###------Routes/Pages------###


@app.route('/')
@app.route('/index')
def index():
    return render_template('mainmenu.html') #Default index page that will open on launch


@app.route('/choose_custom_dsm', methods = ['POST', 'GET']) #Choose Custom DSM page
def choose_custom_dsm():
    if request.method == 'POST': #if a post request was made (from saving DSM on another page), gather data from fields and save to database
        customNameData = request.form.get('custom-name') #The following variables are used for saving the data input from the user
        ecRegexData = request.form.get('ec-regex')
        eidRegexData = request.form.get('eid-regex')
        payloadData = request.form.get('payload')
        
        with app.app_context(): 
            db = get_db()
            db.execute("INSERT INTO custom (dsm_name, ec_regex, eid_regex, payload) VALUES(?,?,?,?)", (customNameData, ecRegexData, eidRegexData, payloadData)) # commit data to db, using ? to prevent sql injection - https://docs.python.org/3/library/sqlite3.html
            db.commit()
        
    
    with app.app_context(): 
        db = get_db()
        custom = db.execute("SELECT id,dsm_name,last_edit FROM custom ORDER BY last_edit desc").fetchall() #display the current available database entries sorted by last edited
        return render_template('choose_custom.html', custom=custom) #render a template with database entries


@app.route('/custom_dsm', methods = ['POST', 'GET']) #Custom DSM page
def custom_dsm():
    if request.method == 'POST':
        customDsmData = request.form.get('cdsm') #pass in the selected option to open from database
    
        with app.app_context():
            db = get_db()
            customdata = db.execute("SELECT id, dsm_name, ec_regex, eid_regex, payload FROM custom WHERE id=?", [customDsmData]).fetchall() # get data from the db, Using id=? for sql injection prevention - https://docs.python.org/3/library/sqlite3.html
            customdataDB = db.execute("SELECT ec_regex, eid_regex, payload FROM custom WHERE id=?", [customDsmData]).fetchone() # get regex specific data from the db using .fetchone so it can be accessed in the following statements
            
            #qpylib.log(customdata2['ec_regex'])
            if (customdataDB['ec_regex'] and customdataDB['eid_regex'] and customdataDB['payload'] ): #if they all exist, perform both regex searches and show fields
                eventCatData = regex_search(customdataDB['ec_regex'], customdataDB['payload']) #search with regex provided on the payload
                eventEIDData = regex_search(customdataDB['eid_regex'], customdataDB['payload']) #search with regex provided on the payload
                return render_template('custom.html', customdata=customdata,  eventCatData=eventCatData, eventEIDData=eventEIDData)  #render a template with database entries and the regex results
                
            elif (customdataDB['ec_regex'] and customdataDB['payload']): #if the EC regex and payload exists, perform the regex search and show fields
                eventCatData = regex_search(customdataDB['ec_regex'],  customdataDB['payload']) #search with regex provided on the payload
                return render_template('custom.html', customdata=customdata, eventCatData=eventCatData) #render a template with database entries and the regex results
                
            elif (customdataDB['eid_regex'] and customdataDB['payload']): #if the EID regex and payload exists, perform the regex search and show fields
                eventEIDData = regex_search(customdataDB['eid_regex'], customdataDB['payload']) #search with regex provided on the payload
                return render_template('custom.html', customdata=customdata, eventEIDData=eventEIDData)  #render a template with database entries and the regex results  
                
            else: #if we have nothing to search regex with, just display the default template
                return render_template('custom.html', customdata=customdata)  #render a template with database entries
         
    else:
         return render_template('custom.html') #render a blank default template 


@app.route('/choose_sample') #Choose Sample page
def choose_sample():
    with app.app_context():
        db = get_db()
        samples = db.execute("SELECT id,dsm_name,last_view FROM sample ORDER BY last_view desc").fetchall() #display the current available database entries sorted by last viewed
        return render_template('choose_sample.html', samples=samples) #render a template with database entries


@app.route('/sample',methods = ['POST', 'GET']) #Sample page
def sample():
    sampleData = request.form.get('dsm') #pass in the selected option to open from database
    #return render_template('sample.html', data=data)
    
    with app.app_context():
        db = get_db()
        sampledata = db.execute("SELECT dsm_name, payload, ec, eid, lstime FROM sample WHERE id=?", sampleData).fetchall() # get data from the db, using ? to prevent sql injection - https://docs.python.org/3/library/sqlite3.html
        #db.execute("UPDATE sample  WHERE id= \"" + data + "\"") #update the last viewed time        
        
        return render_template('sample.html', sampledata=sampledata) #, regex=regex_dict #render a template with database entries


@app.route('/update') #Update page
def update():
    with app.app_context():
        db = get_db()
        versions = db.execute("SELECT dsm_name,current_ver,latest_ver FROM updatedsm ORDER BY dsm_name asc").fetchall() #display the current available database entries
        return render_template('update.html', versions=versions)  #render a template with database entries


@app.route('/suggest_regex', methods = ['POST', 'GET']) #Fill in fields to suggest regex page
def suggest_regex():
    if request.method == 'POST':
        ecRegexData = request.form.get('ec-regex') #pass in the input fields to suggest regex
        eidRegexData = request.form.get('eid-regex')
        payloadData = request.form.get('payload')

        listEcRegexData = [ecRegexData] #add a second variable which turns these into lists, so it doesnt print individual characters in template html
        listEidRegexData = [eidRegexData]
        listPayloadData = [payloadData]
        
        if ecRegexData and eidRegexData: #if we have both filled in, suggest regex on both and return
            
            ecRegexFinal, ecTimeFinal, ecRegexOutput = regex_suggest(payloadData, ecRegexData)
            
            eidRegexFinal, eidTimeFinal, eidRegexOutput = regex_suggest(payloadData, eidRegexData)
            return render_template('suggest_regex.html', listEcRegexData=listEcRegexData, listEidRegexData=listEidRegexData, listPayloadData=listPayloadData, ecRegexFinal=ecRegexFinal, ecTimeFinal=ecTimeFinal, ecRegexOutput=ecRegexOutput, eidRegexFinal=eidRegexFinal, eidTimeFinal=eidTimeFinal, eidRegexOutput=eidRegexOutput ) #render template with all fields filled
        
        elif ecRegexData: #ensures the ec regex input is not empty or just spaces, suggest regex for ec only and return
            ecRegexFinal, ecTimeFinal, ecRegexOutput = regex_suggest(payloadData, ecRegexData)
            return render_template('suggest_regex.html', listEcRegexData=listEcRegexData, listEidRegexData=listEidRegexData, listPayloadData=listPayloadData, ecRegexFinal=ecRegexFinal, ecTimeFinal=ecTimeFinal, ecRegexOutput=ecRegexOutput) #render template with fields filled
        
        elif eidRegexData: #ensures the eid regex input is not empty or just spaces, suggest regex for eid only and return
            eidRegexFinal, eidTimeFinal, eidRegexOutput = regex_suggest(payloadData, eidRegexData)
            return render_template('suggest_regex.html', listEcRegexData=listEcRegexData, listEidRegexData=listEidRegexData, listPayloadData=listPayloadData, eidRegexFinal=eidRegexFinal, eidTimeFinal=eidTimeFinal, eidRegexOutput=eidRegexOutput ) #render template with fields filled
            
        else: #if we don't have a payload, no regex to apply.        
            return render_template('suggest_regex.html', listEcRegexData=listEcRegexData, listEidRegexData=listEidRegexData, listPayloadData=listPayloadData ) #render template with fields filled

    else:
        return render_template('suggest_regex.html') #render a blank default template




