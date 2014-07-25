import sys
import argparse
import yaml
import time
import os
import logging
import pymongo

class mitmargs(argparse.ArgumentParser):
    def __init__(self):
        super(mitmargs, self).__init__("man in the middle daemon")

    def error(self):
        self.print_help()
        sys.exit(2)

    def get_args(self):
        try:
            self.add_argument("-C", "--config", type=str, help="path to yml config file", metavar="")
            self.set_defaults(config="./config.yml")
            return self.parse_args()
        except TypeError:
            print("Given argument(s) is/are incorrect. Usage is as follow:")
            self.error()
        return {}

class mitm(object):
    args = {}
    config = {}
    modules = []
    mod_classes = []
    log = None
    database = None

    def __init__(self, args):
        self.args = args

        self.load_config()
        self.load_log()
        self.load_database()
        self.load_modules()

    def load_config(self):
        config_file = open(self.args.config, 'r')
        self.config = yaml.load(config_file)

    def load_log(self):
        logger_config = self.config.get("logger", {})
        logging.basicConfig(**logger_config)
        self.log = logging.getLogger("mitm")

    def load_database(self):
        database_config = self.config.get("database").get("connection", {})
        try:
            connection = pymongo.Connection(**database_config)
        except pymongo.errors.ConnectionFailure:
            self.log.critical("could not connect to database")
            exit(1)
        self.database = connection[self.config.get("database").get("name", "")]
        if self.database is None:
            self.log.critical("could not select database")
            exit(1)

    def load_modules(self):
        if os.geteuid() != 0:
            self.log.critical("should run as root")
            exit(1)

        self.log.info("modules loading")

        self.modules = [__import__("modules.%s.bootstrap" % (name), fromlist=["*"])
                            for name in self.config.get("kernel").get("modules")]

        self.mod_classes = [getattr(mod, "bootstrap")(self.config, self.database) for mod in self.modules]

    def run(self):
        self.log.info("mitm started")

        try:
            while True:
                for mod in self.mod_classes:
                    mod.invoke()
                time.sleep(self.config.get("kernel").get("invoke_delay"))
        except KeyboardInterrupt:
            self.log.info("mitm is going to stop")
            for mod in self.mod_classes:
                mod.close()

        self.log.info("mitm has downed")

if __name__ == "__main__":
    mitm(mitmargs().get_args()).run()

