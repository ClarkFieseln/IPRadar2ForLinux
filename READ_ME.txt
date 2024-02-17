Instructions to install IPRadar2 (2024.02.14):

**************************************************************************************************
WARNING! 
Some "defense" features may add new rules to your ufw firewall or block network connections by killing processes automatically.
This is the reason why these features are deactivated per default.
If not properly configured, this tool may cause unforeseen system behavior.
In case of problems, the firewall rules can be easily removed from ufw any time you want.
Remember to make regular backups of your firewall settings.
**************************************************************************************************

**************************************************************************************************
DISCLAIMER
Cyber attribution is the process of tracking, identifying and laying blame on the perpetrator of a cyberattack or other hacking exploit.
However, cyber attribution can be challenging, even for cybersecurity experts.
The geographic location of hosts can help you to decide if the host is a friend or a possible attacker.
But this information is just a part of the puzzle.
Attackers may be using a server on a different country to conceal their origin.
Besides this, the used tools to obtain the geolocation of hosts are not always 100% accurate.
Please consider this when using the tool.
**************************************************************************************************

0) - The easiest way to use this tool is by typing:
         pip install ipradar2
     Without administrative privileges you need now to add the installation path to PATH with:
         export PATH=$PATH:<installation_path>
     e.g.: 
         export PATH=$PATH:/home/$USER/.local/bin
         (you can find the installation path with: whereis ipradar2)
     Alternatively, you may run the pip command with sudo:
         sudo pip install ipradar2
     In this case the installation is done in the normal site-packages directory (systemwide).
     Here you may need to add missing tools:
         sudo apt install whois
         sudo apt install traceroute
     Then, just type ipradar2 in a terminal to start the program.
     Besides steps 3) and 4), you don't need to read anymore if you just want to use the tool.
     I suggest you use a separate environment.
   - In case you just want to generate and use a local executable file, then check only the following points:
     3), 4), 6), 7)
   - If you are interested e.g. in debugging or modifying the code, then follow all next steps.

1) Install your favorite IDE.
   Here as an example the description for installing PyCharm, which you can get here:
       https://www.jetbrains.com/pycharm/
   Copy the sources of IPRadar2 provided in GitHub or in CodeProject to some directory:
       GitHub: https://github.com/ClarkFieseln/IPRadar2_for_Linux
       CodeProject: https://www.codeproject.com/Articles/5269206/IP-Radar-2
   Open PyCharm, press the button New Project -> select the location of the folder to place your new project.
   (leave the default path to the virtual enviroment, which is inside your project folder (the new folder is called venv)).
   Select Python39 or greater as the Base interpreter (a different interpeter may be selected, but you may need to adapt the dependencies later).
   Don't inherit global site-packages, I think it is cleaner if we only depend on the things we really need.
   We also don't need to make this new enviroment be available to all projects.

   DEPRECATED?: You then get a Warning Message telling you that the "Directory is Not Empty" -> select "Create from Existing Sources"  (an .idea folder is created).
   Copy the contents of the folder with the sources copied in a previous step.
   
   Go to Edit Configurations -> select "+" to add a new configuration  -> select Python -> call it IPRadar2.
   Select your working directory (highest level where setup.py is located).
   Select IPRadar2.py in Script path   ->  Press OK.

   Select "Install requirements" when the warning appears that some package requirements are not fulfilled.
   (you then get a list, leave all checked, select Install).
   Check also related step 5).

2) If you edit mainWindow.ui, e.g. with Qt Designer, then you can run gen_py_from_ui.sh in a terminal to update Ui_mainWindow.py.
   (but first check step 5), you need some PyQt tools)
    
3) Configure config.ini as required.
   When using pip install, the default folders and files will be created on first run:
       IPRadar2/Config/config.ini
       IPRadar2/Config/locationsResolved.json
       IPRadra2/Output/...
   When working with the code, there is one config.ini file for the executable and a different one when using the IDE:
       IPRadar2/Config/config.ini                      (for IDE - e.g. PyCharm)
       IPRadar2/dist_exec/IPRadar2/Config/config.ini   (for executable)
   IMPORTANT: 
       Note that the default values are just arbitrary and need to be adapted!
       Get familiar with the behavior of the tool before you set ADD_FIREWALL_RULE_BLOCK_BAD_IP to 1 or check the option on the GUI.
       Set ASK_BEFORE_ADDING_RULE=1 at the beginning to double-check before adding rules.
       Set ASK_BEFORE_KILL=1 at the beginning to double-check before killing a process.
       Make a backup of the ufw firewall settings every time you add rules, then you can always roll back to your previous settings.
   Some other configuration parameters you shall ALWAYS check are:
       - CONN_ESTABLISHED_STR
       - ROUTER_IP
   And of course adapt the settings for host location (MY_CITY,...) and map center location (MAP_CENTER_LAT,...).

4) - To use the optional feature sound follow the instructions in Sounds/todo.txt.
   - Install tshark:
         sudo apt update
         sudo apt install tshark
         To allow execution to non-root users answer YES.
     If the tool was already installed on your system, you may want to allow execution to non-root users:
         sudo dpkg-reconfigure wireshark-common
         Answer YES.
     Then you just need to add the user to the wireshark group. Type this:
         sudo usermod -a -G wireshark $USER
     Change your default group:
         newgrp wireshark
     After restart or log you will not need to change your default group anymore.
     Set the corresponding paths in config.ini:
         [tshark]
         tshark_path     (find out with: whereis tshark)
         [dumpcap]
         dumpcap_path    (find out with: whereis dumpcap)

5) Install further tools if required:
    Type in the IDE/PyCharm console or in a system terminal:
       sudo apt install qttools5-dev-tools
       sudo apt install qttools5-dev
       (Then, Qt Designer is installed as designer, and is also in the start menu.)

6) To generate your own executable file there are two possibilities, I recommend the first one (using a virtual environment):
   Generate an executable file in a virtual environment:
   #####################################################
   Check the access rights of gen_exec_in_venv.sh and allow execution if required.
       double-click on gen_exec_in_venv.sh
       (select: execute in a terminal)
   Enter the sudo password when asked.
   Alternatively, you can do it from within the IDE/PyCharm in the console (or in a system terminal) by typing:
      ./gen_exec_in_venv.sh
   Enter the sudo password when asked.
   The generated file ipradar2 will be inside the folder /dist_exec
   Generate an executable file in the system environment:
   ######################################################
   Be aware that in this case you will make packages available to the whole system!
   Check the access rights of gen_exec_in_system.sh and allow execution if required.
       double-click on gen_exec_in_system.sh
       (select: execute in a terminal)
   Enter the sudo password when asked.
   Alternatively, you can do it from within the IDE/PyCharm in the console (or in a system terminal) by typing:
      ./gen_exec_in_system.sh
   Enter the sudo password when asked.
   The generated file ipradar2 will be inside the folder /dist_exec

7) Now you can execute the file ipradar2 from the terminal:
       if you want to use the virtual environment type first:
           source IPRadar2_venv/bin/activate
       if you have not yet restarted or logged out after step 5), you may need change your default group again:
           newgrp wireshark
       now step into folder dist_exec with "cd dist_exec" and run the program with:
           ./ipradar2
       (in this case no firewall rules will be added because you don't have root privileges)
       or with:
           sudo ./ipradar2
       (button Show Map disabled - root cannot open browser => open the .html file from the file explorer or terminal instead,
       and no sounds supported - root cannot play different sounds at the "same" time)
   Of course you can also just double-click on the executable file to run it.
   If you select the option to "run in a terminal" you will be able to see the output when it is directed to the console.

8) Check the Code Project article IPRadar2 that explains how to use the Windows version of the tool, which is similar:
       https://www.codeproject.com/Articles/5269206/IP-Radar-2
   The original code can be found in GitHub:
       https://github.com/ClarkFieseln/IPRadar2ForLinux
   The PyPI project is here:
       https://pypi.org/project/ipradar2

