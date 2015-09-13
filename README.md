Zabbix Manager
==============

One click/command management of your Zabbix server/agent/proxy. Tool similar to 
your package manager (apt/yum), but just for Zabbix.

[![Paypal donate button](http://jangaraj.com/img/github-donate-button02.png)]
(https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=8LB6J222WRUZ4)
   
TODO
====

- search
  try to search provided string in all available actions
  if -a (all) is used then also [Zabbix Github community repo]
  (https://github.com/zabbix/zabbix-community-repos) and [Zabbix Share]
  (https://share.zabbix.com/) are used
  
- list
  listing of available action
  
- installs <action>
  execute selected Zabbix server action

- installa <action>
  execute selected Zabbix agent action
  
- installp <action>     
  execute selected Zabbix proxy action
  
For example:

- search keyword docker:

```
./zm.py search -a docker
```  

- install (compile) Docker module for Zabbix agent:

```
./zm.py installa module-docker-(monitoringartist)
```  

- install (import) Docker template for Zabbix server:

```
./zm.py installs template-docker-(monitoringartist)
```

- install (enable) Selinux for Zabbix agent:

```
./zm.py installs enable-selinux-(monitoringartist)
```

- install (execute) agent troubleshooting:

```
./zm.py installa troubleshooting-(monitoringartist)
```

Author
======

[Devops Monitoring zExpert](http://www.jangaraj.com), who loves monitoring 
systems, which start with letter Z. Those are Zabbix and Zenoss.

Professional monitoring services:

[![Monitoring Artist](http://monitoringartist.com/img/github-monitoring-artist-logo.jpg)]
(http://www.monitoringartist.com)
