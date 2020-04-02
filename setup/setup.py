import mysql.connector
import pymysql #mysql database connecting

def db():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="",
    database="Test",
    )
    mycursor = mydb.cursor()
    mycursor.execute("CREATE DATABASE Test")
    mycursor.execute("CREATE TABLE user (username VARCHAR(255), password VARCHAR(255))")
    mycursor.execute("CREATE TABLE Vulnerabilities (BugID INT AUTO_INCREMENT PRIMARY KEY, url VARCHAR(255), title VARCHAR(1255), description VARCHAR(10000), type VARCHAR(255), print VARCHAR(11255), severity VARCHAR(255)")
db()
