# Perforce exporter for Prometheus

Exports basic information about a remote Perforce server on port 9666. 

    http://localhost:9666/metrics?target=perforce:1666&collectors=users,workspaces,depots


## Authentication/Credentials

Credentials are set up in the config file located at /etc/p4_exporter/conf.yml.

	credentials:
	  perforce1.mydomain.com:1666:
	    username: user1
	    password: mybirthday
	  perforce2.mydomain.com:1666:
	    username: user2
	    password: mypetsname


## Collectors

| Collector   | Data                                              |
| ---------   | ------------------------------------------------- |
| users       | Aggregate data about users                        |
| workspaces  | Aggregate data about workspaces                   |
| depots      | Information for each depot about size and usage   |
| replication | Aggregate data about journal and file replication |


## Query Parameters

| Parameter  | Meaning                                               |
| ---------- | ----------------------------------------------------- |
| target     | address and port of the P4 server, i.e. server:1666   |
| collectors | command delimited list of optional collectors         |
