# DFL-870_snnp log
you must create db 'snmp', create 3 tables:

CREATE TABLE `Alarm_Security_Events` (
	`EventID` INT(15) NOT NULL AUTO_INCREMENT,
	`device` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`dt` DATE NULL DEFAULT NULL,
	`tm` TIME NULL DEFAULT NULL,
	`ID` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`EVENT` VARCHAR(100) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`usr` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`WAN_IP` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`WAN_Port` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`IP` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`PORT` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	PRIMARY KEY (`EventID`) USING BTREE,
	INDEX `IndexDT` (`dt`) USING BTREE
)
COLLATE='utf8mb4_general_ci'
ENGINE=InnoDB
AUTO_INCREMENT=1
;

CREATE TABLE `L2TP_PPTP_Events` (
	`EventID` INT(15) NOT NULL AUTO_INCREMENT,
	`device` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`dt` DATE NULL DEFAULT NULL,
	`tm` TIME NULL DEFAULT NULL,
	`ID` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`EVENT` VARCHAR(100) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`tunnelid` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`sessionid` VARCHAR(50) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`usr` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`remoteIP` VARCHAR(15) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`localip` VARCHAR(15) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`category` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	PRIMARY KEY (`EventID`) USING BTREE
)
COLLATE='utf8mb4_general_ci'
ENGINE=InnoDB
AUTO_INCREMENT=1
;

CREATE TABLE `Other_Events` (
	`EventID` INT(11) NOT NULL AUTO_INCREMENT,
	`device` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`dt` DATE NULL DEFAULT NULL,
	`tm` TIME NULL DEFAULT NULL,
	`ID` VARCHAR(30) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	`EVENT` VARCHAR(100) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
	PRIMARY KEY (`EventID`) USING BTREE
)
COLLATE='utf8mb4_general_ci'
ENGINE=InnoDB
;

If done - creating user for add snmp events

On DFL, enable snmp and specify the IP of this host

DONE!
