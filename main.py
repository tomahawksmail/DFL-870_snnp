#!/usr/bin/env python3
import socketserver
from settings import connect
from datetime import datetime
HOST, PORT = "0.0.0.0", 514

file = open('log.txt', 'a')


class SyslogUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):

        # Парсим это безобразие в список
        data = bytes.decode(self.request[0].strip())
        data = data.replace(data[0:5], '')
        data = str(self.client_address[0]) + data
        data = data.replace(' ', ',')
        data = data.replace('[', ',')
        data = data.replace(']', '')

        info = data.split(',')  # info - это список

        device = info[0]
        dt = datetime.strptime(info[1], '%Y-%m-%d').date()
        tm = datetime.strptime(info[2], '%H:%M:%S').time()
        id = info[6][3:]
        event = info[8][info[8].find("=") + 1:]


        # Разбираем события
        #  admin_login
        if info[6][3:] == '03203000':  # 2.41.32. admin_login (ID: 03203000)
            usr = info[11][info[11].find("=") + 1:]
            WAN_IP = info[18][info[18].find("=") + 1:]
            WAN_Port = info[19][info[19].find("=") + 1:]
            IP = info[20][info[20].find("=") + 1:]
            Port = info[21][info[21].find("=") + 1:]
            sqldata = device, dt, tm, id, event, usr, WAN_IP, WAN_Port, IP, Port
            sqlwrite_Alarm_Security_Events(sqldata)
        #  admin_logout
        elif info[6][3:] == '03203001':  # 2.41.33. admin_logout (ID: 03203001)
            usr = info[10][info[10].find("=") + 1:]
            WAN_IP = ''
            WAN_Port = ''
            IP = info[13][info[13].find("=") + 1:]
            Port = ''
            sqldata = device, dt, tm, id, event, usr, WAN_IP, WAN_Port, IP, Port
            sqlwrite_Alarm_Security_Events(sqldata)
        #  admin_timeout
        elif info[6][3:] == ' 03206000':  # 2.41.39. admin_timeout (ID: 03206000)
            usr = info[10][info[10].find("=") + 1:]
            WAN_IP = ''
            WAN_Port = ''
            IP = info[13][info[13].find("=") + 1:]
            Port = ''
            sqldata = device, dt, tm, id, event, usr, WAN_IP, WAN_Port, IP, Port
            sqlwrite_Alarm_Security_Events(sqldata)
        # Ахтунг, нас атакуют
        elif info[6][3:] == '03203002': # admin_login_failed (ID: 03203002)
            usr = info[12][info[12].find("=") + 1:]
            WAN_IP = info[13][info[13].find("=") + 1:]
            WAN_Port = info[14][info[14].find("=") + 1:]
            IP = info[15][info[15].find("=") + 1:]
            Port = info[16][info[16].find("=") + 1:]
            event = 'admin_login_failed'
            sqldata = device, dt, tm, id, event, usr, WAN_IP, WAN_Port, IP, Port
            sqlwrite_Alarm_Security_Events(sqldata)
        # Системные события
        elif info[6][3:] == '03202500':  # shutdown
            id = '03000006'
            event = 'shutdown'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '03000006':  # startup_normal
            id = '03000006'
            event = 'startup_normal'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '03204001':  # accept_configuration
            id = '03204001'
            event = 'accept_configuration'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '03700408':  # invalid_username_or_password
            id = '03700408'
            event = 'invalid_username_or_password'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '05900196':  # recipient_email_changed_to_drop_address
            id = '05900196'
            event = 'recipient_email_changed_to_drop_address'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '04000021':  # voltage_alarm
            id = '04000021'
            event = 'voltage_alarm'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '04000101':  # free_memory_warning_level
            id = '04000101'
            event = 'free_memory_warning_level'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '04000102':  #  free_memory_warning_level
            id = '04000102'
            event = 'free_memory_warning_level'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '04000011':  #  temperature_alarm
            id = '04000011'
            event = 'temperature_alarm'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        # SMTP
        elif info[6][3:] == '03000006':  # SMTP_rejected_connect
            id = '03000006'
            event = 'SMTP_rejected_connect'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '03000007':  # SMTP_rejected_ehlo_helo
            id = '03000007'
            event = 'SMTP_rejected_ehlo_helo'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '03000008':  # SMTP_rejected_sender
            id = '03000008'
            event = 'SMTP_rejected_sender'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        elif info[6][3:] == '03000009':  # SMTP_rejected_recipient
            id = '03000009'
            event = 'SMTP_rejected_recipient'
            sqldata = device, dt, tm, id, event
            sqlwrite_Other_Events(sqldata)
        # Разбираем L2TP
        elif info[4] == 'L2TP:':
            category = info[4][:4]
            if info[6] == 'id=02800018':
                sessionid = ''
                user = ''
                localIP = ''
                tunnelid = info[9][info[9].find("=") + 1:]
                remoteIP = info[11][9:]
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)

            elif info[6] == 'id=02800016':
                sessionid = info[10][info[10].find("=") + 1:]
                user = info[11][5:]
                localIP = info[14][12:]
                tunnelid = info[9][info[9].find("=") + 1:]
                remoteIP = ''
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)

            elif info[6] == 'id=02800007':
                sessionid = info[10][info[10].find("=") + 1:]
                user = ''
                localIP = ''
                tunnelid = info[11][info[11].find("=") + 1:]
                remoteIP = ''
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)

            elif info[6] == 'id=02800008':
                sessionid = ''
                user = ''
                localIP = ''
                tunnelid = info[10][info[10].find("=") + 1:]
                remoteIP = ''
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)
        # Разбираем PPTP
        elif info[4] == 'PPTP:':
            category = info[4][:4]
            if info[6] == 'id=02700019':
                remoteIP = info[10][9:]
                sessionid = ''
                tunnelid = ''
                user = ''
                localIP = ''
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)
            elif info[6] == 'id=02700012':
                remoteIP = info[11][9:]
                sessionid = ''
                tunnelid = ''
                user = info[12][5:]
                localIP = info[15][12:]
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)
            elif info[6] == 'id=02700008':
                remoteIP = info[10][9:]
                sessionid = ''
                tunnelid = ''
                user = ''
                localIP = ''
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)
            elif info[6] == 'id=02700022':
                remoteIP = info[10][9:]
                sessionid = ''
                tunnelid = ''
                user = ''
                localIP = ''
                sqldata = device, dt, tm, id, event, tunnelid, sessionid, user, remoteIP, localIP, category
                sqlwrite_L2TP_PPTP_Events(sqldata)

        # else:
        #     usr = ''
        #     WAN_IP = info[13][info[13].find("=") + 1:]
        #     WAN_Port = info[14][info[14].find("=") + 1:]
        #     IP = info[15][info[15].find("=") + 1:]
        #     Port = info[16][info[16].find("=") + 1:]
        #     status = 'not determined'
        #     sqldata = device, date, time, id, event, usr, WAN_IP, WAN_Port, IP, Port
        #     # print(sqldata)
        #     # sqlwrite_Alarm_Security_Events(sqldata)


def sqlwrite_L2TP_PPTP_Events(sqldata):
    try:
        cur = connect.cursor()
        cur.execute(
            """INSERT INTO L2TP_PPTP_Events (device, dt, tm, id, event, tunnelid, sessionid, usr, remoteIP, localIP,
            category) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (sqldata[0], sqldata[1], sqldata[2], sqldata[3], sqldata[4], sqldata[5], sqldata[6], sqldata[7], sqldata[8],
             sqldata[9], sqldata[10]))
        connect.commit()
    except Exception as E:
        file.write('start')
        file.write(E)
        file.write('end' + '\n')
        file.close()
    else:
        connect.commit()



def sqlwrite_Alarm_Security_Events(sqldata):
    try:
        cur = connect.cursor()
        cur.execute("""INSERT INTO Alarm_Security_Events (device, dt, tm, id, event, usr, WAN_IP, WAN_Port, IP, Port)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (sqldata[0],  sqldata[1], sqldata[2], sqldata[3], sqldata[4], sqldata[5], sqldata[6], sqldata[7], sqldata[8], sqldata[9]))
    except Exception as E:
        file.write('start')
        file.write(E)
        file.write('end' + '\n')
        file.close()
    else:
        connect.commit()

def sqlwrite_Other_Events(sqldata):
    try:
        cur = connect.cursor()
        cur.execute("""INSERT INTO Other_Events (device, dt, tm, id, event)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (sqldata[0],  sqldata[1], sqldata[2], sqldata[3], sqldata[4]))
    except Exception as E:
        file.write('start')
        file.write(E)
        file.write('end'+'\n')
        file.close()
    else:
        connect.commit()


if __name__ == "__main__":
    try:
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print("Crtl+C Pressed. Shutting down.")
        connect.close()
