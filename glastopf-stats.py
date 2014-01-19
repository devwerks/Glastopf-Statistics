#!/usr/bin/env python
import sqlite3, sys, getopt

#
#	Basic Python script for print out some Stats of your Glastopf Honeypot
#
#	Author:	Johannes Schroeter - www.devwerks.net
#

#Change here the path to your Glastopf Database
dbfileglastopf = '/opt/myhoneypot/db/glastopf.db'

def executeQuery(query):
        
        conn = sqlite3.connect(dbfileglastopf)
        c = conn.cursor()
        
	c.execute(query)
	
	for row in c:
            print(row)
    
def selectQuery():
    
	version()
        
        try:
            opts, args = getopt.getopt(sys.argv[1:],"hq:",["help","query="])
       
        except getopt.GetoptError:
            help()
            sys.exit(2)
        
        for opt, arg in opts:
            
            if opt in ("-h", "--help"):
                help()
                sys.exit()
                
            elif opt in ("-q", "--query"):
                
                #Attacks over last 30 Days
                if arg == '1':
                    sys.stdout.write("#Attacks over last 30 Days\n")
                    querySQL = 'SELECT COUNT(time), SUBSTR(time,-20,12) AS stripped FROM events GROUP BY stripped ORDER BY stripped DESC LIMIT 30'
                    sys.stdout.write("\nQuery: %s\nHits | Date\n" %(querySQL))
                    executeQuery(querySQL)
                    
                #Last 10 events
                elif arg == '2':
                    sys.stdout.write("#Last 10 events\n")
                    querySQL = 'SELECT time,request_url FROM events ORDER BY time DESC LIMIT 10'
                    sys.stdout.write("\nQuery: %s\nTime | Url\n" %(querySQL))
                    executeQuery(querySQL)
                
                #Top10 files
                elif arg == '3':
                    sys.stdout.write("#Top10 files\n")
                    querySQL = 'SELECT COUNT(filename), filename FROM events GROUP BY filename ORDER BY COUNT(filename) DESC LIMIT 10'
                    sys.stdout.write("\nQuery: %s\nNum | Hash\n" %(querySQL))
                    executeQuery(querySQL)
                
                #Busy Attackers
                elif arg == '4':
                    sys.stdout.write("#Busy Attackers\n")
                    querySQL = 'SELECT COUNT(source), SUBSTR(source,-20,14) AS stripped FROM events GROUP BY stripped ORDER BY COUNT(stripped) DESC LIMIT 10'
                    sys.stdout.write("\nQuery: %s\nHits | Host\n" %(querySQL))
                    executeQuery(querySQL)
                
                #Top15 intext requests
                elif arg == '5':
                    sys.stdout.write("#Top15 intext requests\n")
                    querySQL = 'SELECT count, content FROM intext ORDER BY count DESC LIMIT 15'
                    sys.stdout.write("\nQuery: %s\nHits | Request\n" %(querySQL))
                    executeQuery(querySQL)
                
                #Top15 intitle requests
                elif arg == '6':
                    sys.stdout.write("#Top15 intitle requests\n")
                    querySQL = 'SELECT count, content FROM intitle ORDER BY count DESC LIMIT 15'
                    sys.stdout.write("\nQuery: %s\nHits | Request\n" %(querySQL))
                    executeQuery(querySQL)
                
                #Top10 inurl requests
                elif arg == '7':
                    sys.stdout.write("#Top10 inurl requests\n")
                    querySQL = 'SELECT count, content FROM inurl ORDER BY count DESC LIMIT 10'
                    sys.stdout.write("\nQuery: %s\nHits | Request\n" %(querySQL))
                    executeQuery(querySQL)

def version():
    
    sys.stdout.write("\nGlastopf Statistics 0.1\n")
    sys.stdout.write("Author: Johannes Schroeter - www.devwerks.net\n\n")
        
def help():
    
    sys.stdout.write("glastopf-stats.py -q/--query NUMBER\n")
    sys.stdout.write("Example: glastopf-stats.py -q 1\n\n")
    sys.stdout.write("1:Attacks over last 30 Days\n")
    sys.stdout.write("2:Last 10 events\n")
    sys.stdout.write("3:Top10 files\n")
    sys.stdout.write("4:Busy Attackers\n")
    sys.stdout.write("5:Top15 intext requests\n")
    sys.stdout.write("6:Top15 intitle requests\n")
    sys.stdout.write("7:Top10 inurl requests\n\n")

def main():
    
    selectQuery()

    sys.exit()

if __name__ == "__main__":
    main()

