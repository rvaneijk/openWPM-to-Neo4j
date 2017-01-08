

NEO4J 


INSTALLATION

The simplest way is to install the packages:
sudo apt-get install neo4j

You'll also need py2neo:
sudo pip install py2neo


RUNNING

To start the server:
sudo no4j start

This will run a server listening on port 7474 by default. You can have one graph per instance.
If you want to manage multiple graph, you'll have to instance runings on multiple .

By default, the server login password are neo4j/neo4j. To login, visit this page:
http://localhost:7474

If you change the login/password you'll have to modify them in the script


CREATING A GRAPH

Run the command
python openwpm2neo4j path_to_sqlite_db


VIEWING THE GRAPH

This could take a while but you can view the graph before the command returns.
Visit http://localhost:7474
Click on the database icon on the top-left corner.
Click on the "*" under "Relationship types" 

QUERYING 

Here are a few example of queries.

Get 50 hostnames on which doubleclick.net read/set cookies

MATCH (h)-[uses]->(c)-[isreadon]->(Host)
WHERE h.name="doubleclick.net"
RETURN  Host.name
LIMIT 50

Get a graph of domains on which doubleclik read/set cookies

MATCH (h)-[trackson]->(Host)
WHERE h.name="doubleclick.net"
RETURN  trackson
LIMIT 50



