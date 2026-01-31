# Dissertation

Final year dissertation using Python, SQLite3, HTML and CSS.

Note, this is a partially redacted version due to professional usage.

A Docker app that integrates directly into the IBM® QRadar® SIEM.  

There are some enhancements related to common QRadar user support issues and this project idea was created to solve these customer problems, that are related to integration and connections with other cybersecurity products. 

Some of the main concerns include: 
* A way to parse (using regex) the events (log files) of security products which have not yet been supported by IBM, or to enhance existing parsing with customisation. 
* Updating QRadar definitions of supported events
* Helping to solve a lack of awareness on integrations. 

These problems are important to solve as companies seek to increase the detection and response time towards any cyberattacks on their organisation.

 
==============Technologies to be used in this project==============

•	IBM QRadar software (using Red Hat Enterprise Linux Server 7 OS)

•	Python & Python Flask

•	Python Standard Library Re (for Regex) & SQLite3 (for the database) 

•	HTML (with Jinja2 templates) and CSS (for the UI)

•	Docker

==============Project Development Plan==============

a

==============Detailed architecture diagram of project==============

a


==============Folder & file description==============

 (folders are numbered lists, files are bullet point lists):

1. app - the project app to be run within QRadar
    1. static - stores data to be used in html
        * background.png - used for the background of the app
    2. store - where the database gets created (requirement by QRadar otherwise the app data would get wiped)
    3. templates - where each html screen is stored
        * choose_custom.html - The screen for choosing a custom DSM from the database or creating a new one.
        * choose_sample.html - The screen for choosing a sample DSM from the database.
        * custom.html - The screen for displaying the custom DSM, allowing database saving and loading. Used for creating regex and applying it to a select text.
        * layout.html - The screen for the base layout html for the entire app, allowing it to be reused throughout.
        * mainmenu.html - The screen for the main menu, with 3 buttons to take you to the relevant screen sections of the app.
        * sample.html - The screen for displaying a sample DSM and payload, showcasing how the regex is applied and where it gathers the data from.
        * update.html - The screen for displaying updates for official QRadar DSMs provided by IBM, displaying when there is an update and how to get said update

    *  \_\_init\_\_.py - used for initialising the app
    *  schema.sql - used for creating the layout of the database and each table within
    *  views.py - the main python script which is used for creating, updating and retrieving the database, displaying and changing screens and all the backend functionality

==============Installation Instructions==============

To install you need to download IBM® QRadar® Security Intelligence Platform (V7.3.3 or above) and set this up. Instructions and download links are located here: https://www.ibm.com/community/qradar/ce/

Once set up you can install the app with the following guide (or with this youtube video https://youtu.be/IzNmo6iY23M ).

Download the "app" folder from this project. Log in to QRadar, Navigate to the "Admin" page, click on the "Extensions Management" icon located near the top of the page. 

Click "add" and browse for the "app" folder previously downloaded. Click "install immediately" then "add". 

After installation is complete refresh the QRadar page and the app should appear in the navigation bar.

==============Hardware requirements for this project==============

For QRadar Community Edition:

•	Memory minimum: 8 GB RAM 

•	Disk space minimum: 250 GB

•	CPU: 2 cores (minimum) or 6 cores (recommended)

For the project app (instead of the above):

•	Memory minimum: 10GB RAM (Recommended 12GB+)