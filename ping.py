import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2    #floor divide by 2
    count = 0

    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def receive_one_ping(mySocket, ID, timeout, destAddr):
    left_time=timeout
    while 1:
        select_begin=time.time()
        # basically wait for socket for data to come in or until timeout happens
        what_ready = select.select([mySocket], [], [], timeout)
        select_elapsed=(time.time()-select_begin)
        if what_ready[0] == []:  # Timeout
            return "Request timed out."
        #this means it went through, so record the time received
        received_time = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        # TODO: read the packet and parse the source IP address, you will need this part for traceroute
        #since it's the tuple from mySocket.sendto(packet, (destAddr, 1))
        IP=addr[0]
        #get the header
        ICMPHEADER=recPacket[20:28]
        #unpack the struct (it returns a tuple that will correspond to the stuff)
        type_packet,code,checkSum,packet_ID,seq_num=struct.unpack("bbHHh",ICMPHEADER)

        # TODO: calculate and return the round trip time for this ping
        bytes_double=struct.calcsize('d')
        timedata=struct.unpack('d',recPacket[28:28+bytes_double])[0]
        RTT=int((received_time-timedata)*1000)   #to round and make it as milliseconds like in ping

        # TODO: handle different response type and error code, display error message to the user
        if type_packet!=8 and packet_ID==ID:
            return RTT
        if destAddr!=IP:
            return "3: IP Mismatch"
        #dest is unreachable (type 3 response)
        left_time-=select_elapsed
        if left_time<=0:
            return "3: Destination Unreachable"

def send_one_ping(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum

    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(str(header + data))
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    # AF_INET address must be tuple, not str # Both LISTS and TUPLES consist of a number of objects
    mySocket.sendto(packet, (destAddr, 1))
    # which can be referenced by their position number within the object.


def do_one_ping(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details: http://sock- raw.org/papers/sock_raw
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    # Return the current process i
    myID = os.getpid() & 0xFFFF
    send_one_ping(mySocket, destAddr, myID)
    delay = receive_one_ping(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=1,**count):
    if count:
        delays=[]
        sent=0
        received=0
        lost=0
        dest = socket.gethostbyname(host)
        print("Pinging " + host + " using Python:")
        print("")
        for i in range(count['count']):
            delay = do_one_ping(dest, timeout)
            sent+=1
            if delay==None:
                lost+=1
                return "Request timed out"
            else:
                delays.append(delay)
                if type(delay)!=int:
                    print("Request timed out")
                    lost+=1
                else:
                    received+=1
                    print("Reply from " + str(dest) + ":" + " bytes=32 time=" + str(delay) + "ms")
                time.sleep(1)  # one second
        percent_lost=int((lost/float(sent))*100)
        if all(isinstance(item, str) for item in delays):
            print("")
            print("Ping statistics for " + str(dest) + ":")
            print("    Packets: Sent = "+str(sent)+", Received = "+str(received)+", Lost = "+str(lost)+" (" + str(percent_lost)+"% loss),")
            return
        else:
            total_sum=0
            maximum=0
            for i in delays:
                if type(i)==int:
                    if maximum<i:
                        maximum=i
            for i in delays:
                if type(i)==int:
                    total_sum+=i
            avg=(total_sum/len(delays))
            print("")
            print("Ping statistics for "+str(dest)+":")
            print("    Packets: Sent = "+str(sent)+", Received = "+str(received)+", Lost = "+str(lost)+" ("+str(percent_lost)+"% loss),")
            print("Approximate round trip times in milli-seconds:")
            print("    Minimum = "+str(min(delays))+"ms, Maximum = "+str(maximum)+"ms, Average = "+str(avg)+"ms")
            print("")
            return delay
    else:
        # timeout=1 means: If one second goes by without a reply from the server,
        # the client assumes that either the client's ping or the server's pong is lost
        try:
            delays = []
            sent = 0
            received = 0
            lost = 0
            dest = socket.gethostbyname(host)
            print("Pinging " + dest + " using Python:")
            print("")
            # Send ping requests to a server separated by approximately one second
            while 1:
                delay = do_one_ping(dest, timeout)
                #EXTRA CREDIT
                #I modified this so it matches the real ping command in windows
                #by default, an ICMP packet is 32 bytes + 8 bytes for header
                sent+=1
                if delay == None:
                    lost += 1
                    return "Request timed out"
                else:
                    delays.append(delay)
                    if type(delay)!=int:
                        print("Request timed out")
                        lost+=1
                    else:
                        received+=1
                        print("Reply from "+str(dest)+":"+" bytes=32 time="+str(delay)+"ms")
                    time.sleep(1)  # one second
            return delay
        except KeyboardInterrupt:
            percent_lost = int((lost / float(sent)) * 100)
            if all(isinstance(item, str) for item in delays):
                print("")
                print("Ping statistics for " + str(dest) + ":")
                print
                print("    Packets: Sent = " + str(sent) + ", Received = " + str(received) + ", Lost = " + str(
                    lost) + " (" + str(percent_lost) + "% loss),")
                return
            else:
                total_sum = 0
                maximum = 0
                for i in delays:
                    if type(i) == int:
                        if maximum < i:
                            maximum = i
                for i in delays:
                    if type(i) == int:
                        total_sum += i
                avg = (total_sum / len(delays))
                print("")
                print("Ping statistics for " + str(dest) + ":")
                print("    Packets: Sent = " + str(sent) + ", Received = " + str(received) + ", Lost = " + str(
                    lost) + " (" + str(percent_lost) + "% loss),")
                print("Approximate round trip times in milli-seconds:")
                print("    Minimum = " + str(min(delays)) + "ms, Maximum = " + str(maximum) + "ms, Average = " + str(
                    avg) + "ms")
                print("")
                return delay


#ping("www.google.com")
#ping("www.mixi.jp")    #popular japanese website
#ping("www.spiegel.de")   #popular german website
#ping("www.olx.com.eg")   #egyptian shopping site
#ping("terra.com.br",count=4)     #brazilian news site
#ping("google.com",count=4)
#ping("rakuten.co.jp",count=4)
#ping("wwww.fmovies.se",count=10)

if __name__=="__main__":
    fullargs=sys.argv
    args=fullargs[1:]
    website=str(sys.argv[1])
    if len(args)>1:
        count=sys.argv[2]
        ping(website,count=int(count))
    else:
        ping(website)
