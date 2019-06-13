import json
import socket
import hashlib
import threading
import time 
from os import system, _exit, path
import sys
import tkinter as tk
class Peer():

    def __init__(self, ip, port, size):
        #print "initializing"
        self.address = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.address, self.port))
        self.size = size
        self.id = 0
        self.predecessor = []
        self.fingerTable = []
        self.succlist = []
        self.filename = ""
        self.selecting = 0
        self.files = []
        
        #print "initialized"

    def calculateHash(self, size, identity):
        self.size = size
        hash_object = hashlib.sha1(identity)
        hex_dig = hash_object.hexdigest()
        return (int(hex_dig, 16) ) %size

    def initFingerTable(self, ipAddress, port):
        self.predecessor = [ipAddress, port]
        i = 1
        while(i < self.size):
            self.fingerTable.append([(self.id + i) % self.size, self.id, ipAddress, port])
            i = i*2
    def initSucclist(self):
        self.succlist.append([self.fingerTable[0][1], self.fingerTable[0][2], self.fingerTable[0][3]])
        self.succlist.append([self.fingerTable[1][1], self.fingerTable[1][2], self.fingerTable[1][3]])
        self.askForSucc(self.fingerTable[0][2], self.fingerTable[0][3])
    
    def maintainSucclist(self):
        self.succlist[0] = [self.fingerTable[0][1], self.fingerTable[0][2], self.fingerTable[0][3]]
        self.askForSucc(self.fingerTable[0][2], self.fingerTable[0][3])


    def askForSucc(self, ip, port):
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((ip, port))
        sock2.send(json.dumps({"type":"tellSucc", "data": [self.address, self.port] }))
        sock2.close()

    def tellSucc(self, ip, port):
        try:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((ip, port))
            sock2.send(json.dumps({"type":"thisSucc", "data": [self.fingerTable[0][1], self.fingerTable[0][2], self.fingerTable[0][3]] }))
            sock2.close()
        except:
            pass


    def create(self, size):
        #print "creating"
        self.size = size
        hostname = socket.gethostname()    
        IPAddr = socket.gethostbyname(hostname)
        self.id = self.calculateHash(size, IPAddr+":"+ str(self.port))
        self.initFingerTable(IPAddr, self.port)
        self.initSucclist()
        cThread = threading.Thread(target = self.stablize)
        cThread.daemon = True
        cThread.start()
        cThread = threading.Thread(target = self.menu)
        cThread.daemon = True
        cThread.start()
        # cThread = threading.Thread(target = self.takeInput)
        # cThread.daemon = True
        # cThread.start()

        #print "created"
         
    def iWantToJoin(self, joinIp, joinPort):
        self.join(joinIp, joinPort, self.address, self.port)

    def join(self, joinIp, joinPort, joiningIp, joiningPort):
        print "sending join request"
        while(1):
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.connect(( joinIp, joinPort))
                sock2.send(json.dumps({"type":"join", "data": (joiningIp, joiningPort) }))
                sock2.close()
                break
            except:
                time.sleep(1)
                continue
        print "join request sent"
    
    def handleJoinRequest(self, a):
        print "Handling join request"
        id = self.calculateHash(self.size, str(a[0]) + ":" + str(a[1]) )
        hash = id
        myid = self.id
        succ = self.fingerTable[0][1]
        pred = self.calculateHash(self.size, str(self.predecessor[0]) + ":" + str(self.predecessor[1]) )
        if(pred > myid):
            myid += self.size
            succ += self.size
            id += self.size
        if(succ < myid):
            succ += self.size
            if(myid > id):
                id += self.size
        if(myid == succ):
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((str(a[0]), a[1]))
            sock2.send(json.dumps({"type": "joinit" , "data":[self.fingerTable, self.size, self.id]}))
            sock2.close()
        elif((succ > id and id > myid) ):
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((str(a[0]), a[1]))
            sock2.send(json.dumps({"type": "joinit" , "data":[self.fingerTable, self.size, self.id]}))
            sock2.close()

        else:
            id = hash
            prev = self.id
            counter = 0
            for i in range(1, len(self.fingerTable)+1):
                if(not (i == len(self.fingerTable))):
                    succ = self.fingerTable[i][1]
                if(prev > succ):
                    succ += self.size
                    if(prev > id):
                        id += self.size
                #if(succ <= self.fingerTable[i][0]):
                #    succ += self.size
                if(i == len(self.fingerTable) or (succ >= id and id > prev) ):
                    if(self.fingerTable[i-1][2] == self.address and self.fingerTable[i-1][3] == self.port):
                        self.join(self.fingerTable[0][2], self.fingerTable[0][3], a[0], a[1])
                    else:
                        self.join(self.fingerTable[i-1][2], self.fingerTable[i-1][3], a[0], a[1])
                    break
                prev = succ
                counter += 1
         
        
    
    def handleGetFingerRequest(self, a):
        #print "Handling get request"
        hash = self.calculateHash(self.size, str(a[2]) + ":" + str(a[3]) )
        prevH = self.calculateHash(self.size, str(a[0]) + ":" + str(a[1]) )

        hashP = self.calculateHash(self.size, str(self.predecessor[0]) + ":" + str(self.predecessor[1]) )
        succ = self.fingerTable[0][0]
        if(hash < prevH):
            hash += self.size
        if(succ < self.id):
            succ += self.size
        #if(hash < self.id):
        #    hash += self.size
        if((succ >= hash) or succ == self.id):
            #print "Sending reply to Get finger Request"
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((str(a[0]), a[1]))
            sock2.send(json.dumps({"type": "getit" , "data":[self.fingerTable[0], a[4]]}))
            sock2.close()
            # this is succ
            # send its id
            #print "get finger reply sent"
            pass
        elif(self.id >= hash and hash >= hashP):
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((str(a[0]), a[1]))
            sock2.send(json.dumps({"type": "getit" , "data":[[1,1, self.address, self.port], a[2]]}))
            sock2.close()

        else:
            #print "forwarding finger get request"
            all_done = 1
            prev = self.id
            prevI = self.fingerTable[0]
            counter = 0
            for i in range(1, len(self.fingerTable)-1):
                succ = self.fingerTable[i][0]
                if(succ <= prev):
                    succ += self.size
                if(succ >= hash):
                    self.findFinger(self.fingerTable[i-1][2], self.fingerTable[i-1][3], a[0], a[1], a[2], a[3], counter)
                    all_done = 0
                    break
                prev = succ
                counter += 1
            if(all_done == 1):
                self.findFinger(self.fingerTable[len(self.fingerTable)-1][2], self.fingerTable[len(self.fingerTable)-1][3], a[0], a[1], a[2], a[3], counter)

            #for i in self.fingerTable:
            #    succ = i[0]
            #    if(succ <= prev):
            #        succ += self.size
            #    if(succ >= hash and hash >= self.id):
            #        self.findFinger(prevI[2], prevI[3], a[0], a[1], a[2], a[3], counter)
            #        break
            #    prevI = i
            #    prev = succ
            #    counter+=1

            #print "forwarded finger get request"


    def handleGetRequest(self, a):
        #print "Handling get request"
        hash = self.calculateHash(self.size, str(a[0]) + ":" + str(a[1]) )
        hashP = self.calculateHash(self.size, str(self.predecessor[0]) + ":" + str(self.predecessor[1]) )
        succ = self.fingerTable[0][0]
        if(succ < self.id):
            succ += self.size
        #if(hash < self.id):
        #    hash += self.size
        if((succ >= hash) or succ == self.id):
            #print "Sending reply to Get Request"
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((str(a[0]), a[1]))
            sock2.send(json.dumps({"type": "getit" , "data":[self.fingerTable[0], a[2]]}))
            sock2.close()
            # this is succ
            # send its id
            #print "get reply sent"
            pass
        elif(self.id >= hash and hash >= hashP):
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((str(a[0]), a[1]))
            sock2.send(json.dumps({"type": "getit" , "data":[[1,1, self.address, self.port], a[2]]}))
            sock2.close()

        else:
            #print "forwarding get request"
            prev = self.id
            prevI = self.fingerTable[0]
            counter = 0
            for i in self.fingerTable:
                succ = i[0]
                if(succ <= prev):
                    succ += self.size
                if(succ >= hash and hash >= self.id):
                    self.findSucc(prevI[2], prevI[3], a[0], a[1], counter)
                    break
                prevI = i
                prev = succ
                counter+=1

            #print "forwarded get request"

    def findSucc(self, getIp, getPort, myIp, myPort, counter):
        #print "sending successor find request"
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((getIp, getPort))
        sock2.send(json.dumps({"type":"get", "data": [myIp, myPort, counter] }))
        sock2.close()
        #print "successor find request sent"
        return

    def findFinger(self, getIp, getPort, myIp, myPort, thisip, thisport, counter):
        #print "sending finger successor find request"
        try:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((getIp, getPort))
            sock2.send(json.dumps({"type":"getFinger", "data": [myIp, myPort, thisip, thisport, counter] }))
            sock2.close()
        except:
            pass
        #print "finger successor find request sent"
        return


    def constructFingerTable(self, tempFingerTable, initId):
        #print "Constructing finger table"
        properties = []
        counter = 0
        for entry in self.fingerTable:
            succ = self.fingerTable[0][1]
            fingerHash = entry[0]
            if succ < self.id:
                succ += self.size
            if fingerHash < self.id:
                fingerHash += self.size
            if fingerHash <= succ:

                #print "Finger Table entry updated"
                entry[1] = self.fingerTable[0][1]
                entry[2] = self.fingerTable[0][2]
                entry[3] = self.fingerTable[0][3]
                counter += 1
            else:
                #self.findSucc(entry[1], tempFingerTable)
                all_done = 1
                hash = entry[1]
                if hash < self.id:
                    hash += self.size
                prev = initId
                for i in range(1, len(tempFingerTable)-1):
                    succ = tempFingerTable[i][0]
                    if(succ <= prev):
                        succ += self.size
                    if(succ >= hash):
                        self.findFinger(tempFingerTable[i-1][2], tempFingerTable[i-1][3], self.address, self.port, entry[2], entry[3], counter)
                        all_done = 0
                        break
                    prev = succ
                if(all_done == 1):
                    self.findFinger(tempFingerTable[len(tempFingerTable)-1][2], tempFingerTable[len(tempFingerTable)-1][3], self.address, self.port, entry[2], entry[3], counter)
                counter += 1
        #print "finger Table constucted requests sent"
        #print self.fingerTable

    def informSucc(self):
        #print "imforming new succ"
        hostname = socket.gethostname()    
        IPAddr = socket.gethostbyname(hostname)
        try:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((self.fingerTable[0][2], self.fingerTable[0][3]))
            sock2.send(json.dumps({"type":"MePred", "data": [IPAddr, self.port] }))
            sock2.close()
        except:
            pass
        #print "new succ informed"



    def handleJoining(self, data):
        #print "Joining"
        hostname = socket.gethostname()    
        IPAddr = socket.gethostbyname(hostname)
        self.size = data[1]
        self.id = self.calculateHash(self.size, IPAddr+":"+ str(self.port))
        self.initFingerTable(IPAddr, self.port)
        self.fingerTable[0][1] = data[0][0][1]
        self.fingerTable[0][2] = data[0][0][2]
        self.fingerTable[0][3] = data[0][0][3]
        self.informSucc()
        self.constructFingerTable(data[0], data[2])
        self.initSucclist()
        cThread = threading.Thread(target = self.stablize)
        cThread.daemon = True
        cThread.start()
        cThread = threading.Thread(target = self.menu)
        cThread.daemon = True
        cThread.start()
        # cThread = threading.Thread(target = self.takeInput)
        # cThread.daemon = True
        # cThread.start()


        #print "Joined"
        #print self.fingerTable

    def handleGetting(self, data):
        #print "Getting"
        ip = str(data[0][2])
        port = data[0][3]
        index = data[1]
        hash = self.calculateHash(self.size, ip + ":" + str(port))
        #print hash
        self.fingerTable[index][1] = hash
        self.fingerTable[index][2] = ip
        self.fingerTable[index][3] = port
        #print "Got"
        #print self.fingerTable

    def handleChangeSucc(self, data):
        hash = self.calculateHash(self.size, str(data[0]) + ":" + str(data[1]))
        self.fingerTable[0][1] = hash
        self.fingerTable[0][2] = data[0]
        self.fingerTable[0][3] = data[1]
        self.informSucc()
    
    def handleChangePred(self, data):
        #print "changing predecessor"
        self.predecessor = data
        #print self.predecessor
        #p4-Refreshrint "predecessor changed"



    def handleHeartBeat(self, data):
        #print "heart Beat Request Recieved"
        #print data
        #print self.predecessor
        if(self.predecessor[0] != data[0] or self.predecessor[1] != data[1]):
            #print "succ changing"
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((data[0], data[1]))
            sock2.send(json.dumps({"type":"changeSucc", "data": [self.predecessor[0], self.predecessor[1]] }))
            sock2.close()
            #print "succ changed"

    def get(self, id, index, sIp, sPort, type):
        myid = self.id
        succ = self.fingerTable[0][1]
        pred = self.calculateHash(self.size, str(sIp) + ":" + str(sPort))
        hash = id
        if(pred > myid):
            myid += self.size
            succ += self.size
            id += self.size
        if(succ < myid):
            succ += self.size
            if(myid > id):
                id += self.size
        if(myid == succ):
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((sIp, sPort))
            sock2.send(json.dumps({"type":"get reply", "data": [type, self.id, self.address, self.port, index] }))
            sock2.close()
        elif(succ >= id and id >= myid):
            for i in range(3):
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.connect((sIp, sPort))
                    sock2.send(json.dumps({"type":"get reply", "data": [type, self.fingerTable[0][1], self.fingerTable[0][2], self.fingerTable[0][3], index] }))
                    sock2.close()
                    break
                except:
                    time.sleep(1)

        else:
            id = hash
            all_done = 1
            prev = self.fingerTable[0][1]
            counter = 0
            for i in range(1, len(self.fingerTable)+1):
                id = hash
                if(not (i == len(self.fingerTable))):
                    succ = self.fingerTable[i][1]
                if(succ < prev):
                    succ += self.size
                    if(prev > id):
                        id += self.size
                if( i == len(self.fingerTable) or (succ >= id and id >= prev) ):
                    for j in range(3):
                        try:
                            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock2.connect((self.fingerTable[i-1][2], int(self.fingerTable[i-1][3])))
                            sock2.send(json.dumps({"type":type, "data": [hash, index, sIp, sPort, type] }))
                            sock2.close()
                            break
                        except:
                            if(j == 2):
                                self.fingerTable[i-1][1] = self.fingerTable[(i)%len(self.fingerTable)][1]
                                self.fingerTable[i-1][2] = self.fingerTable[(i)%len(self.fingerTable)][2]
                                self.fingerTable[i-1][3] = self.fingerTable[(i)%len(self.fingerTable)][3]

                    all_done = 0
                    break
                prev = self.fingerTable[i][1]

                counter += 1
            


    def fingerGet(self, id, ip, port, index):
        self.fingerTable[index][1] = id
        self.fingerTable[index][2] = ip
        self.fingerTable[index][3] = port
        #print self.fingerTable
   
    
    def handleDownload(self, id, ip, port, index):
        for i in range(3):
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.connect((ip, port))
                sock2.send(json.dumps({"type":"upload", "data": [self.filename, self.address, self.port,] }))
                sock2.close()
                break
            except:
                pass

   
    def handleUpload(self, id, ip, port, index):
        self.upload(self.filename, ip, port, 2)

    def uploadto(self, filename, ip, port):
        if filename in self.files:
            self.upload(filename, ip, port)


    def upload(self, filename, ip, port, a=1):
        for i in range(5):
            try: 
                size =path.getsize(filename)
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.connect((ip, port))
                if(a == 1):
                    sock2.send(json.dumps(dict({"type":"initDownload", "data": [filename, size, [self.fingerTable[0][1], self.fingerTable[0][2], self.fingerTable[0][3] ]] })))
                else:
                    sock2.send(json.dumps(dict({"type":"initDownload2", "data": [filename, size, [self.fingerTable[0][1], self.fingerTable[0][2], self.fingerTable[0][3] ]] })))
                time.sleep(1)
                f = open(filename,'rb')
                print 'Sending...'
                l = f.read(2048)
                while (l):
                    print 'Sending...'
                    sock2.send(l)
                    time.sleep(0.01)
                    l = f.read(2048)
                f.close()
                print "Done Sending"
                sock2.close()
                break
            except:
                if i == 4:
                    print "upload failed"

    def recievedata(self, filename, c, size, suc):
        f = open(filename, 'wb')
        while (True): 
            print "Receiving..."
            l = c.recv(2048)        
            f.write(l)
            if len(l) < 2048:
                break
        f.close()
        print "Done Receiving"
        size2 = path.getsize(filename)
        print size
        print size2
        c.close()
        if(size != size2):
            self.handleDownload(suc[0], suc[1], suc[2], 0)
            return
        if(filename not in self.files):
            self.files.append(filename)
        # if(self.fingerTable[0][2] !=self.address or self.fingerTable[0][3] != self.port ):
            # self.upload(filename, self.fingerTable[0][2], self.fingerTable[0][3])
    def recievedata2(self, filename, c, size, suc):
        f = open(filename, 'wb')
        while (True):
            print "Receiving..."
            l = c.recv(2048)        
            f.write(l)
            if len(l) < 2048:
                break
        f.close()
        print "Done Receiving"
        size2 = path.getsize(filename)
        c.close()
        print size
        print size2

        if(size != size2):
            self.handleDownload( suc[0], suc[1], suc[2])
            return

        if(filename not in self.files):
            self.files.append(filename)
        if(self.fingerTable[0][2] !=self.address or self.fingerTable[0][3] != self.port ):
            self.upload(filename, self.fingerTable[0][2], self.fingerTable[0][3])


    def handleConnections(self):
        #print "Started Handling Connections"
        while(1):
            try:
                c, a = self.sock.accept()
                #print "connection joined"
                message = json.loads((c.recv(1024)))
                if(message['type'] == 'initDownload'):
                    cThread = threading.Thread(target = self.recievedata, args = (message["data"][0], c, message["data"][1], message["data"][2] ))
                    cThread.daemon = True
                    cThread.start()
                    continue 
                if(message['type'] == 'initDownload2'):
                    cThread = threading.Thread(target = self.recievedata2, args = (message["data"][0], c, message["data"][1], message["data"][2] ))
                    cThread.daemon = True
                    cThread.start()
                    continue 

                else:
                    c.close()
            except KeyboardInterrupt:
                self.leaving();
            except Exception:
                print message["data"]
                print "failed"
                continue
            if(message['type'] == 'join'):
                #print "Peer wants to join"
                cThread = threading.Thread(target = self.handleJoinRequest, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "joinit"):
                #print "Peer accepted join request" 
                cThread = threading.Thread(target = self.handleJoining, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            
            elif(message["type"] == "tellSucc"):
                #print "Peer accepted join request" 
                cThread = threading.Thread(target = self.tellSucc, args = (message["data"]))
                cThread.daemon = True
                cThread.start()
            
            elif(message["type"] == "thisSucc"):
                #print "Peer accepted join request" 
                #print self.succlist
                self.succlist[1][0] = message["data"][0]
                self.succlist[1][1] = message["data"][1]
                self.succlist[1][2] = message["data"][2]

            elif(message["type"] == "get"):
                #print "Peer wants to get"
                cThread = threading.Thread(target = self.handleGetRequest, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "getFinger"):
                #print "Peer wants to get"
                cThread = threading.Thread(target = self.handleGetFingerRequest, args = (message["data"],))
                cThread.daemon = True
                cThread.start()

            elif(message["type"] == "getit"):
                #print "Peer accepted get request"
                #print message["data"]
                cThread = threading.Thread(target = self.handleGetting, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "stablize"):
                #print "Heart Beat"
                #print message["data"]
                cThread = threading.Thread(target = self.handleHeartBeat, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "changeSucc"):
                #print "changing succ"
                #print message["data"]
                cThread = threading.Thread(target = self.handleChangeSucc, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "MePred"):
                #print "changing pred"
                #print message["data"]
                cThread = threading.Thread(target = self.handleChangePred, args = (message["data"],))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "fingerGet"):
                #print "changing pred"
                #print message["data"]
                cThread = threading.Thread(target = self.get, args = (message["data"]))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "get reply"):
                #print "changing pred"
                if (message["data"][0] == "fingerGet"):
                    cThread = threading.Thread(target = self.fingerGet, args = (message["data"][1:]))
                    cThread.daemon = True
                    cThread.start()
                elif (message["data"][0] == "download"):
                    cThread = threading.Thread(target = self.handleDownload, args = (message["data"][1:]))
                    cThread.daemon = True
                    cThread.start()
                elif (message["data"][0] == "uploadthis"):
                    cThread = threading.Thread(target = self.handleUpload, args = (message["data"][1:]))
                    cThread.daemon = True
                    cThread.start()

            elif(message["type"] == "download"):
                cThread = threading.Thread(target = self.get, args = (message["data"]))
                cThread.daemon = True
                cThread.start()
            elif(message["type"] == "uploadthis"):
                cThread = threading.Thread(target = self.get, args = (message["data"]))
                cThread.daemon = True
                cThread.start()

            elif(message['type'] == 'upload'):
                cThread = threading.Thread(target = self.uploadto, args = (message["data"]))
                cThread.daemon = True
                cThread.start()
    
    def guiMenu(self):
        root = Tkinter.Tk()
        
        # canvas = Tkinter.Canvas(root, height=HEIGHT, width=WIDTH)
        # canvas.pack()

        # frame =Tkinter.Frame(root, bg="light slate blue", bd=5)
        # frame.place(relx=0.5, rely=0.1, relwidth=0.75, relheight=0.1)
        
        # dButton = Tkinter.Button ( top, bg = "green", activebackground = "dark olive green" )
        # dButton.place()


        top.mainloop()

    def menu(self):
        while(1):
            #time.sleep(10)
            #while(self.selecting):
            #    continue

            system('clear')  
            print "ID: " + str(self.id) + " | " + str(self.address) + " | "+ str(self.port)
            print "Finger Table: "
            for i in self.fingerTable:
                print str(i[0]) + " | " + str(i[1]) + " | " + str(i[2]) +" | "+ str(i[3])
            pred = self.calculateHash(self.size, self.predecessor[0]+ ":" + str(self.predecessor[1]))
            print "Predessor: " + str(pred) + " | "+ str(self.predecessor[0]) + " | " + str(self.predecessor[1])
            print "Sucessors:"
            for i in self.succlist:
                print str(i[0]) + " | " + str(i[1]) + " | " + str(i[2])

            print ""
            print "Options: "
            print "1-Exit"
            print "2-Download"
            print "3-Upload"
            print "4-Refresh"
            option = ""
            option = raw_input("Enter input")
            self.selecting = 1
            if option == "1":
                self.leaving()
            elif option == "2":
                self.download()
            elif option == "3":
                self.uploadThis()

    def stablize(self):
        while(1):
            time.sleep(20)
            for i in range(3):
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.connect((self.fingerTable[0][2], int(self.fingerTable[0][3])))
                    sock2.send(json.dumps({"type": "stablize" , "data":[self.address, self.port]}))
                    sock2.close()
                    break
                except:
                    time.sleep(2)
                    if i == 2:
                        self.fingerTable[0][1] = self.succlist[1][0]
                        self.fingerTable[0][2] = self.succlist[1][1]
                        self.fingerTable[0][3] = self.succlist[1][2] 
                        self.informSucc()
            
            time.sleep(1)
            self.maintainSucclist()
            time.sleep(1)

            for i in range(len(self.fingerTable)):
                #print "lub finger"
                time.sleep(1)
                if (not (self.fingerTable[i][2] == self.address and self.fingerTable[i][3] == self.port)):
                    for j in range(3):
                        try:
                            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock2.connect((self.fingerTable[i][2], int(self.fingerTable[i][3])))
                            sock2.send(json.dumps({"type":"", "data": [] }))
                            sock2.close()
                            break
                        except:
                            if(j == 2):
                                self.fingerTable[i][1] = self.fingerTable[(i+1)%len(self.fingerTable)][1]
                                self.fingerTable[i][2] = self.fingerTable[(i+1)%len(self.fingerTable)][2]
                                self.fingerTable[i][3] = self.fingerTable[(i+1)%len(self.fingerTable)][3]
                time.sleep(1)
                id = self.fingerTable[i][0]
                try:
                    self.get(id, i, self.address, self.port,"fingerGet")
                except:
                    pass
                time.sleep(1)
    
    def takeInput(self):
        while (1):
            option = ""
            option = raw_input("")
            self.selecting = 1
            if option == "1":
                self.leaving()
            elif option == "2":
                self.download()
            elif option == "3":
                self.uploadThis()


    def download(self):
        self.filename = raw_input("Enter File Name")
        self.selecting = 0
        id = self.id
        hash = self.calculateHash(self.size, self.filename)
        filehash = hash
        print hash
        phash = self.calculateHash(self.size, self.predecessor[0] +":"+ str(self.predecessor[1]))
        if(id < phash):
            id += self.size
            if(phash > filehash):
                filehash += self.size

        if(filehash < id and filehash > phash):
            print "You have the File"
            time.sleep(1)
        else:
            print "getting"
            self.get(hash, 0, self.address, self.port, "download")

    def uploadThis(self):
        self.filename = raw_input("Enter File Name")
        self.selecting = 0
        id = self.id
        hash = self.calculateHash(self.size, self.filename)
        filehash = hash
        print hash
        phash = self.calculateHash(self.size, self.predecessor[0] +":"+ str(self.predecessor[1]))
        if(id < phash):
            id += self.size
            if(phash > filehash):
                filehash += self.size

        if(filehash < id and filehash > phash):
            print "Uploaded: you are succ"
            time.sleep(1)
            if(self.filename not in self.files):
                self.files.append(self.filename)
            if(self.fingerTable[0][2] !=self.address or self.fingerTable[0][3] != self.port ):
                self.upload( file, self.fingerTable[0][2], self.fingerTable[0][3])

        else:
            print "getting"
            self.get(hash, 0, self.address, self.port, "uploadthis")

        

    def leaving(self):
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((self.fingerTable[0][2], self.fingerTable[0][3]))
        sock2.send(json.dumps({"type":"MePred", "data": [self.predecessor[0], self.predecessor[1]] }))
        sock2.close()
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((self.predecessor[0], self.predecessor[1]))
        sock2.send(json.dumps({"type":"changeSucc", "data": [self.fingerTable[0][2], self.fingerTable[0][3]] }))
        sock2.close()
        for file in self.files:
            if(self.fingerTable[0][2] !=self.address or self.fingerTable[0][3] != self.port ):
                self.upload( file, self.fingerTable[0][2], self.fingerTable[0][3])
        ## transfer files to succ##############################################################################################
        self.sock.close()
        print "Exiting..."
        _exit(1)

  
    def start(self, option):
        self.sock.listen(15)
        if option == "create":
            self.create(100)
        elif option == "join":
            hostname = socket.gethostname()    
            IPAddr = socket.gethostbyname(hostname)    

            joinIp = IPAddr#"0.0.0.0" #input("Enter IP address of Node to join")
            joinPort = int(raw_input("Enter Port of Node to join"))
            self.iWantToJoin(joinIp, joinPort)

        self.handleConnections()








if __name__ == '__main__':
    hostname = socket.gethostname()    
    IPAddr = socket.gethostbyname(hostname)    
    ip = IPAddr#"0.0.0.0" #input("Enter IP")
    port = int(raw_input("Enter Port"))
    peer = Peer(ip, port, 100)
    option = raw_input("create or join")
    peer.start(option) 
