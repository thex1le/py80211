import threading
import time
# custom imports
import Parse80211
import PyLorcon2

#debug imports
import pdb
import sys
import os

class Toolkit80211:
    """
    Group of classes for working with 80211
    """
    air = ""
    chanlock = 0

    def __init__(self,interface):
        """
        interface = string 
        currently assumes all cards are to be opened in monitor mode
        """
        #print self.chanlock
        # open the card up and gain a a context to them
        # create a dict with interface name and context
        try:
            self.moniface = {"ctx":PyLorcon2.Context(interface)}
        except PyLorcon2.Lorcon2Exception,e:
            print "%s is the %s interface there?" %(e, interface)
            sys.exit(-1)
        # place cards in injection/monitor mode
        self.moniface["ctx"].open_injmon()
        self.moniface["name"] = self.moniface["ctx"].get_vap()
        self.air = self.Airview(self.moniface)
        self.air.start()

    def open(self):
        """
        retruns air object
        """
        return self.air

    def exit(self):
        """
        Close card context
        """
        self.moniface["ctx"].close()

    class ChannelHop(threading.Thread):
        """
        Control a card and cause it to hop channels
        Only one card per instance
        """
        def __init__(self,interface):
            """
            set the channel hopping sequence
            expects lorcon injmon() context
            """
            self.lock = 0
            threading.Thread.__init__(self)
            threading.Thread.daemon = True
            self.iface = interface
            self.pause = False
            # dwell for 3 time slices on 1 6 11
            # default is 3/10 of a second
            # got the lists from kismet config file
            # thanks dragorn!
            self.channellist = [1,6,11,14,2,7,3,8,4,9,5,10,
                36,40,44,48,52,56,60,64,149,153,157,161,165]
            self.hopList = []
            self.current = 0
            self.checkChannels()

        def checkChannels(self):
            """
            card drivesr suck, determine what channels 
            a card supports before we start hopping
            """
            # try setting 802.11ab channels first
            # this may not work depending on 5ghz dfs
            # reverse so we start with 5ghz channels first
            for ch in self.channellist:
                try:
                    self.iface.set_channel(ch)
                except PyLorcon2.Lorcon2Exception:
                    continue
                self.hopList.append(ch)
        
        def pause(self):
            """
            Pause the channel hopping
            """
            self.pause = True

        def unpause(self):
            """
            Unpause the channel hopping
            """
            self.pause = False
        
        def setchannel(self, channel):
            """
            Set a single channel
            expects channel to be an int
            returns -1 if channel isnt supported
            #should raise an exception if this is the case
            """
            while self.lock == 1:
                print "!!!!!!!!!!!!!!Waiting for lock...!!!!!!!!!!!!"
                time.sleep(2)
                if channel in self.hopList:
                    self.iface.set_channel(channel)
                    return 0
                else:
                    return -1

        def hop(self, dwell=.4):
            """
            Hop channels
            """
            while True:
                # hopping is paused though loop still runs
                if self.pause == True | self.lock == 1:
                    continue
                for ch in self.hopList:
                    try:
                        self.iface.set_channel(ch)
                    except PyLorcon2.Lorcon2Exception:
                        continue
                    self.current = ch
                    if ch in [1,6,11]:
                        # dwell for 4/10 of a second
                        # we want to sit on 1 6 and 11 a bit longer
                        time.sleep(dwell)
                    else:
                        time.sleep(.2)
        
        def run(self):
            """
            start the channel hopper
            """
            self.hop()

    class Airview(threading.Thread):
        """
        Grab a snapshot of the air
        whos connected to who
        whats looking for what
        # note right now expecting to deal with only one card
        # will need to refactor code to deal with more then one in the future
        # dong this for time right now
        """
        def __init__(self, interface):
            """
            Open up a packet parser for a given interface
            Thread the instance
            """
            self.hopper = ""
            threading.Thread.__init__(self)
            threading.Thread.daemon = True
            # get interface name for use with pylibpcap
            self.iface = interface["name"]
            # get context for dealing with channel hopper
            self.ctx = interface["ctx"]
            # open up a parser
            self.rd = Parse80211.Parse80211(self.iface)
            # key = bssid, value = essid
            self.bss = {}
            # load up latest beacon packet for an AP
            self.apData = {}
            # note fake AP's can end up in here.. need to solve this
            # key = essid, value [bssid, bssid]
            self.ess = {}
            # this may not work for WDS, though ignoring wds for now
            # key = mac, value=assoication
            self.clients = {}
            # probes from a given client
            self.clientProbes = {}
            # info on clients
            self.clientsExtra = {}
            #the above works fine, but let's get more efficient
            self.view = {}
            # ap = key{essid},value{bssid,clients}
            # clients = key{mac},value{probelist[]}
            
            # dict to store last 5 essids seen for a bssid
            #key = bssid value=[ssid,ssid....]
            self.vSSID = {}

        @staticmethod
        def pformatMac(hexbytes):
            """
            Take in hex bytes and pretty format them 
            to the screen in the xx:xx:xx:xx:xx:xx format
            """
            mac = []
            for byte in hexbytes:
                mac.append(byte.encode('hex'))
            return ':'.join(mac)

        def verifySSID(self, bssid, uessid):
            """
            its possible to get a mangled ssid
            this allows us to check last 5 seen 
            to see if they are mangled or its been changed
            bssid = bssid in hex of ap in question
            uessid = essid in hex to verify
            if all 5 dont match return False, else return True
            """
            for essid in self.vSSID[bssid]:
                if uessid != essid:
                    # blank it out
                    self.vSSID[bssid] = []
                    return False
            return True

        def updateClient(self, frame):
            """
            Update self.clients var based on ds bits
            """
            bssid = frame["bssid"]
            src = frame["src"]
            dst = frame["dst"]
            ds = frame["ds"]
            #bcast and multicast addrs
            self.packetBcast = {
                "oldbcast": '\x00\x00\x00\x00\x00\x00',  # old broadcast address
                "l2": '\xff\xff\xff\xff\xff\xff',     # layer 2 mac broadcast
                "ipv6m": '\x33\x33\x00\x00\x00\x16',  # ipv6 multicast
                "stp": '\x01\x80\xc2\x00\x00\x00',    # Spanning Tree multicast 802.1D
                "cdp": '\x01\x00\x0c\xcc\xcc\xcc',    # CDP/VTP mutlicast address
                "cstp": '\x01\x00\x0C\xCC\xCC\xCD',   # Cisco shared STP Address
                "stpp": '\x01\x80\xc2\x00\x00\x08',   # Spanning Tree multicast 802.1AD
                "oam": '\x01\x80\xC2\x00\x00\x02',    # oam protocol 802.3ah
                "ipv4m": '\x01\x00\x5e\x00\x00\xCD',  # ipv4 multicast
                "ota" : '\x01\x0b\x85\x00\x00\x00'    # Over the air provisioning multicast
                }
            if ds == 0:
                # broadcast/adhoc
                self.clients[src] = "Not Associated"
                if src in self.clientsExtra.keys():
                    self.clientsExtra[src]['wired'] = False
                else:
                    self.clientsExtra[src] = {'wired':False}
            elif ds == 1:
                # station to ap
                self.clients[src] = bssid
                if src in self.clientsExtra.keys():
                    self.clientsExtra[src]['wired'] = False
                else:
                    self.clientsExtra[src] = {'wired':False}
                return
            elif ds == 2:
                # ap to station
                # check for wired broadcasts
                if dst in self.packetBcast.values():
                    #were doing with a wired broadcast
                    #make sure we show its connected to an ap
                    self.clients[src] = bssid
                    if src in self.clientsExtra.keys():
                        # dont set a wireless client to wired
                        if self.clientsExtra[src]['wired'] is not False:
                            self.clientsExtra[src]['wired'] = True
                    else:
                        self.clientsExtra[src] = {'wired':True}
                # deal with ipv6 mutlicast
                elif dst[:2] == self.packetBcast["ipv6m"][:2]:
                    #were doing with a wired broadcast
                    #make sure we show its connected to an ap
                    self.clients[src] = bssid
                    if src in self.clientsExtra.keys():
                        # dont set a wireless client to wired
                        if self.clientsExtra[src]['wired'] is not False:
                            self.clientsExtra[src]['wired'] = True
                    else:
                        self.clientsExtra[src] = {'wired':True}
                else:
                    self.clients[dst] = bssid
                    if src in self.clientsExtra.keys():
                        self.clientsExtra[src]['wired'] = False
                    else:
                        self.clientsExtra[src] = {'wired':False}
                return
            elif ds == 3:
                # wds, were ignoring this for now
                return
            else:
                return

        def parse(self):
            """
            Grab a packet, call the parser then update
            The airview state vars
            """
            while True:
                #TODO: we may need to set semaphore here?
                self.hopper.lock = 1
                self.channel = self.hopper.current
                frame = self.rd.parseFrame(
                            self.rd.getFrame())
                self.hopper.lock = 0
                #release semaphore here -- we have what we came for
                # beacon frames
                if frame == None:
                    # we cant parse the frame
                    continue
                if frame == -1:
                    # frame is mangled
                    continue
                if frame["type"] == 0 and frame["stype"] == 8:
                    # beacon packet
                    bssid = frame["bssid"]
                    essid = frame["essid"]
                    # update bss list, we dont check for keys
                    # as it allows the essid for a given bssid to be updated
                    self.bss[bssid] = essid
                    # update ess list
                    if essid in self.ess.keys():
                        self.ess[essid].append(bssid)
                    else:
                        self.ess[essid]=[bssid]
                    #update all info about ap
                    self.apData[bssid] = frame
                    if bssid in self.vSSID.keys():
                        ssidList = self.vSSID[bssid]
                        if len(ssidList) > 3:
                            # remove first item
                            ssidList.pop(0)
                            # append new one to back
                            ssidList.append(essid)
                            self.vSSID[bssid] = ssidList
                        else:
                            self.vSSID[bssid].append(essid)
                    else:
                        self.vSSID[bssid] = [essid]
                    continue
                elif frame["type"] == 2 and frame["stype"] in range(0,16):
                    #applying to all data packets
                    self.updateClient(frame)
                if frame["type"] == 0 and frame["stype"] in [4]:
                    # update client list
                    self.updateClient(frame)
                    # process probe for essid
                    src = frame["src"]
                    essid = frame["essid"]
                    if frame["src"] in self.clientProbes.keys():
                        if essid != '':
                            self.clientProbes[src][essid] = ""
                    else:
                        # use dict behaivor to remove duplicates
                        if essid != '':
                            self.clientProbes[src] = {essid:""}
        
        def getCapr(self, wiredc=False):
            """
            Parse clients list to build current list 
            of bssids and their clients
            set wiredc to True to include wired devices discovered by broadcast
            """
            self.capr = {}
            for client in self.clients.keys():
                # include or exclude wired devices
                if wiredc is False:
                  if client in self.clientsExtra.keys():
                    if self.clientsExtra[client]['wired'] is False:
                        # skip the wired devices
                        continue
                bssid = self.clients[client]
                if bssid != "Not Associated":
                    if bssid not in self.capar.keys():
                        self.capar[bssid] = [client]
                    else:
                        self.capar[bssid].append(client)

        def getProbes(self, cmac):
            """
            return a list of probe requests 
            for a given client
            """
            if cmac in self.clientProbes.keys():
                return self.clientProbes[cmac].keys()
            else:
                return None

        def run(self):
            """
            start the parser
            """
            # need to start channel hopping here
            self.hopper = Toolkit80211.ChannelHop(self.ctx)
            self.hopper.start()
            self.parse()
