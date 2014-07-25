import logging
import threading
import SocketServer
import socket
import time

class bootstrap(object):
    config = {}
    log = None
    database = None
    telnet_server = None

    def __init__(self, config, database):
        self.config = config
        self.log = logging.getLogger("mitm.telnet")
        self.database = database
        self.start_telnet_server()
        self.log.info("telnet module loaded")

    def start_telnet_server(self):
        self.telnet_server = TelnetServer(self.config, self.log, self.database)
        self.telnet_server.start()

    def invoke(self):
        pass

    def close(self):
        if self.telnet_server:
            self.telnet_server.stop()
            self.telnet_server.join()
        self.log.info("telnet module has downed")

class TelnetServerHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        self.connection.setblocking(0)
        self.wfile.write("\nmitm>")
        while self.server.mitm_running:

            try:
                self.data = self.rfile.readline().strip()
            except:
                time.sleep(0.01)
                continue

            if self.data == '':
                break

            if self.data.find(' ') > 0:
                command, args = self.data.split(' ', 1)
            else:
                command = self.data
                args = ""

            if not (self.server.mitm_commands.get(command) is None):
                self.server.mitm_commands[command].invoke(args, self.rfile, self.wfile)
            else:
                self.wfile.write("\n command '%s' not found " % (command))
            self.wfile.write("\nmitm>")

class TelnetServer(threading.Thread):
    mod_commands = {}
    commands = {}
    config = None
    log = None
    database = None
    server = None

    def __init__(self, config, log, database):
        super(TelnetServer, self).__init__()
        self.config = config
        self.log = log
        self.database = database

    def init_server(self):
        try:
            HOST, PORT = (self.config.get("telnet").get("host"), self.config.get("telnet").get("port"))
            self.server = SocketServer.TCPServer((HOST, PORT), TelnetServerHandler)
            self.server.mitm_commands = self.commands
            self.server.mitm_running = True
        except socket.error:
            self.log.critical("telnet server could not start")

    def load_commands(self):
        self.log.info("commands loading")

        self.mod_commands = dict([(name, __import__("modules.telnet.commands.%s" % (name), fromlist=["*"]))
                            for name in self.config.get("telnet").get("commands")])

        self.commands = dict([(command, getattr(self.mod_commands.get(command), "command")(self.config, self.database))
                                for command in self.mod_commands.keys()])

    def stop(self):
        if self.server:
            self.server.mitm_running = False
            time.sleep(2)
            self.server.shutdown()

    def run(self):
        self.load_commands()
        self.init_server()
        self.log.info("telnet thread started")
        if self.server:
            self.server.serve_forever()
        self.log.info("telnet thread stoped")