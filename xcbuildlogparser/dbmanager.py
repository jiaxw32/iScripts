import sqlite3
import os
import uuid
from datetime import datetime
import threading
from threading import Thread,Timer
from queue import Queue

class DBManager(Thread):
    species = "DBManager"

    def __init__(self, filename=":memory:", autocommit=True, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._filename = filename
        self.autocommit = autocommit
        self._connection = None
        self.reqs= Queue()
        self.connect()
        self.start()

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, value):
        self._filename = value

    @property
    def connection(self):
        return self._connection

    def connect(self):
        if self.autocommit:
            self._connection = sqlite3.connect(self.filename, isolation_level=None, check_same_thread=False)
        else:
            self._connection = sqlite3.connect(self.filename, check_same_thread=False)
        self.connection.text_factory = str

    def close(self):
        # self._connection.close()
        self.execute('--close--')
    
    def commit(self):
        self.execute('--commit--')

    def run(self):
        try:
            cursor = self.connection.cursor()
            cursor.execute('PRAGMA synchronous=OFF')
            while True:
                req, args, res = self.reqs.get()
                if req == '--close--':
                    break
                elif req == '--commit--':
                    self.connection.commit()
                else:
                    cursor.execute(req, args)
                    if res is not None:
                        for rec in cursor:
                            res.put(rec)
                        res.put('--no more--')
                    if self.autocommit:
                        self.connection.commit()
        except Exception as ex:
            print(f"{datetime.now()}: {ex}")
        # finally:
            # self.connection.close()
    
    def execute(self, req, args=None, res=None):
        self.reqs.put((req, args or tuple(), res))

    def select(self, req, args=None):
        res = Queue()
        self.execute(req, args, res)
        while True:
            rec = res.get()
            if rec == '--no more--':
                break
            yield rec

    def table_exist(self, tablename:str):
        sql = f"select * from sqlite_master where type = 'table' and name = ?"
        ret = self.select(sql, (tablename,))
        if ret is None:
            return False
        else:
            return len(list(ret)) > 0

class XCLogDBManager(DBManager):
    _instance_lock = threading.Lock()

    def __new__(cls, filename, autocommit=True, *args, **kwargs):
        if not hasattr(XCLogDBManager, "_instance"):
            with XCLogDBManager._instance_lock:
                if not hasattr(XCLogDBManager, "_instance"):
                    XCLogDBManager._instance = super(XCLogDBManager, cls).__new__(cls, *args, **kwargs)
        return XCLogDBManager._instance

    def __init__(self, filename=":memory:", autocommit=True):
        super(XCLogDBManager, self).__init__(filename, autocommit)

    @staticmethod
    def sharedinstance():
        global db
        return db

    def create_buildlog_table(self, tablename):
        sql = f"CREATE TABLE IF NOT EXISTS {tablename} (row_uuid TEXT PRIMARY KEY, build_identifier TEXT, identifier TEXT, parentid TEXT, domain TEXT, xcbtype TEXT, detail_step_type TEXT, title TEXT, signature TEXT, document_url TEXT, fetched_from_cache integer,start_timestamp real, end_timestamp real, duration real, compilation_end_timestamp real, compilation_duration real, start_date TEXT, enddate TEXT, machine_name TEXT, schema TEXT, architecture TEXT, build_status TEXT, warning_count integer, warnings TEXT, error_count integer, errors TEXT, notes TEXT, sub_steps TEXT);"
        self.execute(sql)
    
    def save_build_log(self, dic, tablename):
        sql = f"insert into {tablename} values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        rowid = str(uuid.uuid4())
        params = (rowid,  dic["buildIdentifier"],  dic["identifier"],  dic["parentIdentifier"],  dic["domain"],  dic["type"],  dic["detailStepType"],  dic["title"],  dic["signature"],  dic["documentURL"],  dic["fetchedFromCache"],  float(dic["startTimestamp"]),  float(dic["endTimestamp"]),  float(dic["duration"]),  float(dic["compilationEndTimestamp"]),  float(dic["compilationDuration"]),  dic["startDate"],  dic["endDate"],  dic["machineName"],  dic["schema"],  dic["architecture"],  dic["buildStatus"],  dic["warningCount"],  str(dic["warnings"]),  dic["errorCount"],  str(dic["errors"]),  str(dic["notes"]),  str(dic["subSteps"]))
        self.execute(sql, params)

filedir = os.path.split(os.path.realpath(__file__))[0]
dbfile = os.path.join(filedir, "data/xcbuildlog.db")
print(dbfile)
db = XCLogDBManager(dbfile)