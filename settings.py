import pymysql
# Настройки подключения к MySQL
host = '127.0.0.1'
user = 'login'
password = 'Passw0rd'
db = 'SNMP'

connect = pymysql.connect(host=host, user=user, password=password, db=db, use_unicode=True, charset='utf8')
