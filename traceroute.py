import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2
# The packet that we shall send to each router along the path is the ICMP echo # request packet, which is exactly what we had used in the ICMP ping exercise. # We shall use the same packet that we built in the Ping exercise


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
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


def build_packet():
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.
    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    # So the function ending should look like this
    ID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
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
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            # TODO: create ICMP socket, connect to destination IP, set timeout and time-to-live
            icmp = socket.getprotobyname("icmp")
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            sock.settimeout(TIMEOUT)
            try:
                # TODO: create ICMP ping packet, record the time delay of getting response detect timeout
                packet=build_packet()
                sock.sendto(packet,(hostname,0))
                start=time.time()
                start_select=time.time()
                detect=select.select([sock],[],[],timeLeft)
                selectLength=(time.time()-start_select)
                recvPacket, addr = sock.recvfrom(1024)
                rec_time = time.time()
                timeLeft = timeLeft - selectLength
                if detect[0]==[]:   #if there's no socket
                    #print("%-15s %-15s %s" % (str(ttl), "*", "Request timed out"))
                    pass
                #if timeLeft<0:
                 #   print("%-15s %-15s %s" % (str(ttl), "*", "Request timed out"))  #time exceeded (type '11')
            except socket.timeout:   #time exceeded (type 11) I just chose to print it like the real thing
                print("%-15s %-15s %s" % (str(ttl), "*", "Request timed out"))
            else:
                # TODO: parse and handle different response type
                # Hint: use wireshark to get the byte location of the response type
                icmpHeader=recvPacket[20:28]
                request_type,code,check,packetID,seq=struct.unpack("bbHHh",icmpHeader)
                err=0
                try:
                    name=str(socket.gethostbyaddr(addr[0])[0])
                except:
                    name=str(addr[0])
                    err=1
                if request_type==11 or request_type==3:
                    if err!=1:
                        print("%-15s %-15s %s" %(str(ttl),str(int(round((rec_time-start)*1000)))+" ms",name+" ["+str(addr[0]+"]")))
                    else:
                        print("%-15s %-15s %s" % (
                        str(ttl), str(int(round((rec_time - start) * 1000)))+" ms", name))
                elif request_type==0:
                    b = struct.calcsize("d")
                    delivered_time = struct.unpack("d", recvPacket[28:28 + b])[0]
                    if err!=1:
                        print("%-15s %-15s %s" % (str(ttl), str(int(round((rec_time - delivered_time) * 1000)))+" ms", name + " [" + str(addr[0] + "]")))
                    else:
                        print("%-15s %-15s %s" % (str(ttl), str(int(round((rec_time - delivered_time) * 1000)))+" ms", name))
                    return
                else:
                    print("Unexpected Error Occurred")
                    break
            finally:
                # TODO: close the socket
                sock.close()


if __name__=="__main__":
    fullargs = sys.argv
    args = fullargs[1:]
    website = str(sys.argv[1])
    error=0
    try:
        ip=socket.gethostbyname(website)
    except:
        #type 3
        print("\nDestination Unreachable")
        error=1
    if error!=1:
        print("")
        print("Tracing route to "+website+" ["+ip+"] ")
        print("over a maximum of "+str(MAX_HOPS)+" hops:")
        print("")
        get_route(website)
        #get_route("google.com")
        #get_route("www.morganstanley.com")