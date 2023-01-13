import sqlite3
from datetime import datetime
from threading import Thread
from queue import Queue
import uuid
from datetime import datetime

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
    
    def get_tasksize(self):
        return self.reqs.qsize()

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
    
    def query_result_exist(self, sql, params):
        ret = self.select(sql, params)
        if ret is None:
            return False
        else:
            return len(list(ret)) > 0

    def table_exist(self, tablename:str):
        sql = f"select * from sqlite_master where type = 'table' and name = ?"
        ret = self.select(sql, (tablename,))
        if ret is None:
            return False
        else:
            return len(list(ret)) > 0

class HouseTradeStatDBManager(DBManager):

    def __init__(self, filename=":memory:", autocommit=True):
        super(HouseTradeStatDBManager, self).__init__(filename, autocommit)
        self._house_trade_data = "bj_zjw_house_trade_stat"
        self.init_database()
    
    def init_database(self):
        if self.table_exist(self._house_trade_data) == False:
            sql = f"CREATE TABLE IF NOT EXISTS {self._house_trade_data} (row_uuid TEXT PRIMARY KEY, title TEXT, trade_date TEXT, online_sign_count INTEGER, online_sign_area real, house_sign_count INTEGER, house_sign_area real, createdatetime real);"
            self.execute(sql)
    
    def save_trade_data(self, data):
        title = data["title"]
        exist_sql = f"select row_uuid from {self._house_trade_data} where title like ?;"
        exist_params = (title,)

        if self.query_result_exist(exist_sql, exist_params) == True:
            print(f"<{title}> data already exist.")
            return

        sql = f"insert into {self._house_trade_data} values(?, ?, ?, ?, ?, ?, ?, ?)"
        rowid = str(uuid.uuid4())
        ts = datetime.timestamp(datetime.now())
        params = (rowid, data["title"], data["trade_date"], data["online_sign_count"],  data["online_sign_area"],  data["house_sign_count"],  data["house_sign_area"],  ts)
        self.execute(sql, params)


if __name__ == "__main__":
    pass