Anspass: Credential storage for utilities that implement the askpass interface


License:
--------
All code for anspass, anspassd, anspass-ctrl, and anspass-lib is licensed as
LGPL so that other applications can use it as a library even though the
application is not just a library.

Description:
-----------

anspass is a daemon/client utility to save and retrieve credentials by other
utilities that implement the askpass interface.  See
https://git-scm.com/docs/gitcredentials for details on how git uses this
credential management system.


Setting up the credential management system involves setting up the anspass
path and token in environment variables:
ANSPASS_PATH
ANSPASS_TOKEN

ANSPASS_PATH is the path where the databases will be stored on disk.

ANSPASS_TOKEN is a one-time use variable that is reported when starting the
anspass daemon (anspassd).






Example:
-------

Set the path to the directory where the encrypted credentials will be stored:
export ANSPASS_PATH=<user home directory>/.anspass

Set up a database by running the daemon and
specifying an optional password:

#./anspassd
Token: 64BF31E20E3CB3D4


Read the return from the start of the daemon and export as ASNPASS_TOKEN:
export ASNPASS_TOKEN=64BF31E20E3CB3D4

Set git or other utilities askpass credential management system to use the anspass binary as the client.

export GIT_ASKPASS=<path to bins>/anspass

Use the 3rd party utility directly:

$ git clone https://windshare.windriver.com/ondemand/remote.php/gitsmart/WRLinux-8-Core/agent-proxy.git
Cloning into 'agent-proxy'...
remote: Counting objects: 61, done.
remote: Total 61 (delta 0), reused 0 (delta 0)
Unpacking objects: 100% (61/61), done.
Checking connectivity... done.






anspass-ctrl options:
--------------------

Adding credentials:
anspass-ctrl --add <url>
eg:
anspass-ctrl --add https://windshare.windriver.com

Answer the prompts for a username and password.

Changing credentials:

anspass-ctrl --update <url>

Answer the prompts for a username and password.



Deleting credentials:

anspass-ctrl --del https://windshare.windriver.com

Answer the prompts for a username.

Resetting the credentials (forget all stored credentials):

anspass-ctrl --reset

