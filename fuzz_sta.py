from scapy.all import *
from sta_settings import *
import string
import random
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)
txcount = 0


class session:

    def __init__(
            self,
            sleep_time=1,
            log_level=logging.INFO,
            timeout=5.0
    ):
        '''
        Extends pgraph.graph and provides a container for architecting protocol dialogs.

        @type  sleep_time:         Float
        @kwarg sleep_time:         (Optional, def=1.0) Time to sleep in between tests
        @type  log_level:          Integer
        @kwarg log_level:          (Optional, def=logger.INFO) Set the log level
        @type  timeout:            Float
        @kwarg timeout:            (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out
        '''

        self.sleep_time = sleep_time
        self.timeout = timeout
        self.proto = socket.SOCK_RAW

        # Initialize logger
        self.logger = logging.getLogger("logger")
        self.logger.setLevel(log_level)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] -> %(message)s')

        consolehandler = logging.StreamHandler()
        consolehandler.setFormatter(formatter)
        consolehandler.setLevel(log_level)
        self.logger.addHandler(consolehandler)

    def fuzz(self):

        self.server_init()
        while 1:

            def error_handler(e, msg, sock=None):
                if sock:
                    sock.close()
                msg += "\nException caught: %s" % repr(e)
                self.logger.critical(msg)
                sys.exit(0)

            while 1:
                try:
                    sock = conf.L2socket(type=ETH_P_ALL, iface=IFACE)
                except Exception, e:
                    error_handler(e, "failed creating socket", sock)

                # if the user registered a pre-send function, pass it the sock and let it do the deed.
                try:
                    self.pre_send(sock)
                except Exception, e:
                    error_handler(e, "pre_send() failed", sock)
                    continue

                # now send the current node we are fuzzing.
                try:
                    self.transmit(sock)  # enter point
                except Exception, e:
                    error_handler(e, "failed transmitting fuzz node", sock)
                    continue
                # if we reach this point the send was successful for break out of the while(1).
                break

            # if the user registered a post-send function, pass it the sock and let it do the deed.
            # we do this outside the try/except loop because if our fuzz causes a crash then the post_send()
            # will likely fail and we don't want to sit in an endless loop.
            try:
                self.post_send(sock)
            except Exception, e:
                error_handler(e, "post_send() failed", sock)

            # done with the socket.
            sock.close()

            # delay in between test cases.
            self.logger.info("Delay for %f seconds" % self.sleep_time)
            time.sleep(self.sleep_time)

    def post_send(self, sock):
        '''
        Overload or replace this routine to specify actions to run after to each fuzz request.
            pre_send() - req - callback ... req - callback - post_send()
        '''
        pass

    def pre_send(self, sock):
        return True
        """
        Returns whenever STA active scanning is detected.
        """
        global STA_MAC

        sess.logger.info("waiting for active scanning from %s" % STA_MAC)
        scapy.all.sniff(iface=IFACE, store=False, lfilter=lambda x: x.haslayer(Dot11ProbeReq), stop_filter=lambda x: str(x.addr2) == STA_MAC)
        sess.logger.info("active scanning detected from %s" % STA_MAC)

    def server_init(self):
        '''
        Called by fuzz() on first run (not on recursive re-entry) to initialize variables, web interface, etc...
        '''
        global log_file_name

        try:
            import signal
            self.signal_module = True
        except:
            self.signal_module = False
        if self.signal_module:
            def exit_abruptly(signal, frame):
                self.logger.critical("SIGINT received ... exiting")
                log_file = open(log_file_name, "a")
                log_file.seek(-2, os.SEEK_END)
                log_file.truncate()
                log_file.write('\n\t]\n')
                log_file.write('}')
                log_file.close()
                sys.exit(0)

            signal.signal(signal.SIGINT, exit_abruptly)

    def transmit(self, sock):

        def rand_str(y):
            tmp = []
            tmp2 = []
            if y % 2 == 0:
                for x in range(y / 2):
                    ch = random.choice(string.hexdigits) + random.choice(string.hexdigits)
                    tmp.append(chr(int(ch, 16)))
                    tmp2.append(ch)
                rand_str = ''.join(tmp)
                rand_str_origin = ''.join(tmp2)
            elif y % 2 == 1:
                for x in range(y / 2):
                    ch = random.choice(string.hexdigits) + random.choice(string.hexdigits)
                    if x == y / 2:
                        ch = random.choice(string.hexdigits) + '0'
                    tmp.append(chr(int(ch, 16)))
                    tmp2.append(ch)
                rand_str = ''.join(tmp)
                rand_str_origin = ''.join(tmp2)
            return rand_str, rand_str_origin

        is_crash = False
        global txcount
        global log_file_name
        global test_count

        data_sent, data = rand_str(random.randint(0, 1024))

        # Authentification pckt
        # pckt = RadioTap()/Dot11(subtype = 11, addr1=STA_MAC, addr2 =AP_DUMMY, addr3=AP_DUMMY)/fuzz(Dot11Auth())

        # Data pckt
        pckt = RadioTap(version=0, pad=0, present=18479) / \
               Dot11(proto=0, subtype=0, type=2, ID=0, addr1=STA_MAC, addr2=AP_DUMMY, addr3=AP_DUMMY) / \
               data_sent
        resp_pckt = RadioTap(version=0, pad=0, present=18479) / \
                    Dot11(proto=0, FCfield=8, subtype=5, addr4=None, addr2='b8:27:eb:08:71:c2', addr3='b8:27:eb:08:71:c2', addr1='5c:99:60:98:dc:27', SC=10848, type=0, ID=14849) / \
                    Dot11ProbeResp(timestamp=time.time(), cap=261, beacon_interval=100) / \
                    Dot11Elt(info='rp', ID=0, len=2) / \
                    Dot11Elt(info='\\x82\\x84\\x8b\\x96$0Hl', ID=1, len=8) / \
                    Dot11Elt(info='\\x01', ID=3, len=1) / \
                    Dot11Elt(info='US \\x01\\x0b\\x1e', ID=7, len=6) / \
                    Dot11Elt(info='\\x00', ID=32, len=1) / \
                    Dot11Elt(info='\\x13\\x00', ID=35, len=2) / \
                    Dot11Elt(info='\\x00', ID=42, len=1) / \
                    Dot11Elt(info='\\x0c\\x12\\x18`', ID=50, len=4) / \
                    Dot11Elt(info='!\\x00\\x1f\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',ID=45, len=26) / \
                    Dot11Elt(info='\\x01\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',ID=61, len=22) / \
                    Dot11Elt(info='\\x04', ID=127, len=1) / \
                    Dot11Elt(info='\\x00\\x10\\x18\\x02\\x00\\x10\\x0c\\x00\\x00', ID=221, len=9) / \
                    Dot11Elt(info="\\x00P\\xf2\\x02\\x01\\x01\\x80\\x00\\x03\\xa4\\x00\\x00\'\\xa4\\x00\\x00BC^\\x00b2/\\x00",ID=221, len=24) / \
                    Dot11Elt(info='K_', ID=15, len=194)

        # original probe response pckt
        # resp_pckt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + self.get_frequency(1) + '\xc0\x00\xc0\x01\x00\x00') / \
        #             Dot11(proto=0, FCfield=8, subtype=5, addr4=None, addr2=AP_DUMMY, addr3=AP_DUMMY, addr1=STA_MAC, SC=10848, type=0, ID=14849) / \
        #             Dot11ProbeResp(timestamp=time.time(), cap=261, beacon_interval=100) / \
        #             Dot11Elt(info='rp', ID=0, len=2) / \
        #             Dot11Elt(info='\\x82\\x84\\x8b\\x96$0Hl', ID=1, len=8) / \
        #             Dot11Elt(info='\\x01', ID=3, len=1) / \
        #             Dot11Elt(info='US \\x01\\x0b\\x1e', ID=7, len=6) / \
        #             Dot11Elt(info='\\x00', ID=32, len=1) / \
        #             Dot11Elt(info='\\x13\\x00', ID=35, len=2) / \
        #             Dot11Elt(info='\\x00', ID=42, len=1) / \
        #             Dot11Elt(info='\\x0c\\x12\\x18`', ID=50, len=4) / \
        #             Dot11Elt(info='!\\x00\\x1f\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',ID=45, len=26) / \
        #             Dot11Elt(info='\\x01\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',ID=61, len=22) / \
        #             Dot11Elt(info='\\x04', ID=127, len=1) / \
        #             Dot11Elt(info='\\x00\\x10\\x18\\x02\\x00\\x10\\x0c\\x00\\x00', ID=221, len=9) / \
        #             Dot11Elt(info="\\x00P\\xf2\\x02\\x01\\x01\\x80\\x00\\x03\\xa4\\x00\\x00\'\\xa4\\x00\\x00BC^\\x00b2/\\x00",ID=221, len=24) / \
        #             Dot11Elt(info='K_', ID=15, len=194)

        try:
            # data pckt send
            sendp(pckt, iface=IFACE, socket=sock)

            # probe response send
            sendp(resp_pckt, iface=IFACE, socket=sock)

            txcount = txcount + 1
            rcv = sniff(iface=IFACE, store=True, stop_filter=lambda x: x.addr1 == AP_DUMMY, timeout=self.timeout)

            if "<Sniffed: TCP:0 UDP:0 ICMP:0 Other:0>" in str(rcv):
                is_crash = True

            log_file = open(log_file_name, "a")
            log_file.write("\t\t{")
            log_file.write("\"no\" : {0},".format(txcount))
            log_file.write("\"state\" : {0},".format("data"))

            if is_crash:
                log_file.write("\"crash\" : \"y\",")
            else:
                log_file.write("\"crash\" : \"n\",")
            log_file.write("\"payload\" : {")
            log_file.write("\"data\" : \"{0}\"".format(data))
            log_file.write("}")
            log_file.write("},\n")
            log_file.close()

            # Save sending packet
            wrpcap(log_file_name + 'snd.pcap', pckt)
            # Save received packet
            wrpcap(log_file_name + 'rcv.pcap', rcv)

        except Exception, inst:
            self.logger.error("Socket error, send: %s" % inst)


sess = session(timeout=1)
sess.fuzz()
