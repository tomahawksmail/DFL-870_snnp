✅ DFL-870 SNMP Log Setup Guide

🗄️ 1. Create Database
```
CREATE DATABASE snmp
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_general_ci;

USE snmp;
```
🧱 2. Create Tables

Table 1 — Alarm_Security_Events

```
CREATE TABLE Alarm_Security_Events (
  EventID INT(15) NOT NULL AUTO_INCREMENT,
  device VARCHAR(30) DEFAULT NULL,
  dt DATE DEFAULT NULL,
  tm TIME DEFAULT NULL,
  ID VARCHAR(30) DEFAULT NULL,
  EVENT VARCHAR(100) DEFAULT NULL,
  usr VARCHAR(30) DEFAULT NULL,
  WAN_IP VARCHAR(30) DEFAULT NULL,
  WAN_Port VARCHAR(30) DEFAULT NULL,
  IP VARCHAR(30) DEFAULT NULL,
  PORT VARCHAR(30) DEFAULT NULL,
  PRIMARY KEY (EventID) USING BTREE,
  INDEX IndexDT (dt) USING BTREE
) ENGINE=InnoDB
  AUTO_INCREMENT=1
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_general_ci;
```
Table 2 — L2TP_PPTP_Events
```
CREATE TABLE L2TP_PPTP_Events (
  EventID INT(15) NOT NULL AUTO_INCREMENT,
  device VARCHAR(30) DEFAULT NULL,
  dt DATE DEFAULT NULL,
  tm TIME DEFAULT NULL,
  ID VARCHAR(50) DEFAULT NULL,
  EVENT VARCHAR(100) DEFAULT NULL,
  tunnelid VARCHAR(50) DEFAULT NULL,
  sessionid VARCHAR(50) DEFAULT NULL,
  usr VARCHAR(30) DEFAULT NULL,
  remoteIP VARCHAR(15) DEFAULT NULL,
  localip VARCHAR(15) DEFAULT NULL,
  category VARCHAR(30) DEFAULT NULL,
  PRIMARY KEY (EventID) USING BTREE
) ENGINE=InnoDB
  AUTO_INCREMENT=1
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_general_ci;

```

Table 3 — Other_Events
```
CREATE TABLE Other_Events (
  EventID INT(11) NOT NULL AUTO_INCREMENT,
  device VARCHAR(30) DEFAULT NULL,
  dt DATE DEFAULT NULL,
  tm TIME DEFAULT NULL,
  ID VARCHAR(30) DEFAULT NULL,
  EVENT VARCHAR(100) DEFAULT NULL,
  PRIMARY KEY (EventID) USING BTREE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_general_ci;

```

👤 3. Create User for SNMP Event Insertion

```
CREATE USER 'snmpwriter'@'%' IDENTIFIED BY 'StrongPasswordHere';

GRANT INSERT, SELECT ON snmp.* TO 'snmpwriter'@'%';

FLUSH PRIVILEGES;

```

🔧 4. Configure DFL-870

Log in to the DFL-870 web interface.

Navigate to SNMP settings.

Enable SNMP.

Set the Notification / Trap Destination IP to the IP address of this database host.

Apply and save configuration.

🎉 DONE!
