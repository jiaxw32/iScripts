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

    def table_exist(self, tablename:str):
        sql = f"select * from sqlite_master where type = 'table' and name = ?"
        ret = self.select(sql, (tablename,))
        if ret is None:
            return False
        else:
            return len(list(ret)) > 0


class WeChatDB(DBManager):
    def __init__(self, filename=":memory:", autocommit=True):
        super(WeChatDB, self).__init__(filename, autocommit)
    
    def query_group_chat_msg(self, tablename):
        sql = f"select Message from {tablename} where Type=1 order by CreateTime;"
        print(f"sql: {sql}")
        iterator = self.select(sql)
        msglist = list()
        for row in iterator:
            msg: str = row[0].strip()
            '''
            群聊消息，格式如下所示，截断移除第一行发言人
            
            liewmn:
            需要放在网页某个播放器里
            '''
            idx = msg.find(':\n')
            if idx != -1:
                msg = msg[idx+2:]
            msglist.append(msg)
        return msglist
    
    def query_personal_chat_msg(self, tablename):
        sql = f"select Message from {tablename} where Type=1 order by CreateTime;"
        print(f"sql: {sql}")
        iterator = self.select(sql)
        msglist = list()
        for row in iterator:
            msg: str = row[0].strip()
            msglist.append(msg)
        return msglist

if __name__ == '__main__':
    filedir = os.path.split(os.path.realpath(__file__))[0]
    dbfile = os.path.join(filedir, 'message_4.sqlite')
    db = WeChatDB(dbfile)
    li = db.query_group_chat_msg("Chat_cy")
    print(li)