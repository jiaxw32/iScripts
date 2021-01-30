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

class XCLogDBManager(DBManager):

    def __init__(self, filename=":memory:", autocommit=True):
        super(XCLogDBManager, self).__init__(filename, autocommit)
        self._xcbuildlog_table = "xc_buildlog"
        self.create_buildlog_metadata_table()
        self.create_buildlog_table()
    
    @property
    def xcbuildlog_table(self):
        return self._xcbuildlog_table

    @staticmethod
    def sharedinstance():
        global db
        return db

    def create_buildlog_table(self):
        sql = f"CREATE TABLE IF NOT EXISTS {self.xcbuildlog_table} (row_uuid TEXT PRIMARY KEY, build_identifier TEXT, identifier TEXT, parentid TEXT, domain TEXT, xcbtype TEXT, detail_step_type TEXT, title TEXT, signature TEXT, document_url TEXT, fetched_from_cache integer,start_timestamp real, end_timestamp real, duration real, compilation_end_timestamp real, compilation_duration real, start_date TEXT, enddate TEXT, machine_name TEXT, schema TEXT, architecture TEXT, build_status TEXT, warning_count integer, warnings TEXT, error_count integer, errors TEXT, notes TEXT, sub_steps TEXT);"
        self.execute(sql)
    
    def create_buildlog_metadata_table(self):
        sql = f"CREATE TABLE IF NOT EXISTS xc_buildlog_metadata (row_uuid TEXT PRIMARY KEY, identifier TEXT, title TEXT, filename TEXT, filepath TEXT, scheme_name TEXT, starttimestamp real, endtimestamp real, duration real, signature TEXT, classname TEXT, orig_logs TEXT);"
        self.execute(sql)
    
    def save_buildlog_metadata(self, params):
        sql = f"insert into xc_buildlog_metadata values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        self.execute(sql, params)
    
    def save_build_log(self, dic):
        sql = f"insert into {self.xcbuildlog_table} values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        rowid = str(uuid.uuid4())
        params = (rowid,  dic["buildIdentifier"],  dic["identifier"],  dic["parentIdentifier"],  dic["domain"],  dic["type"],  dic["detailStepType"],  dic["title"],  dic["signature"],  dic["documentURL"],  dic["fetchedFromCache"],  float(dic["startTimestamp"]),  float(dic["endTimestamp"]),  float(dic["duration"]),  float(dic["compilationEndTimestamp"]),  float(dic["compilationDuration"]),  dic["startDate"],  dic["endDate"],  dic["machineName"],  dic["schema"],  dic["architecture"],  dic["buildStatus"],  dic["warningCount"],  str(dic["warnings"]),  dic["errorCount"],  str(dic["errors"]),  str(dic["notes"]),  str(dic["subSteps"]))
        self.execute(sql, params)

    def count_ccompilation_duration(self):
        sql = f"select count(*) as filecount, sum(duration) as durations \
        FROM {self.xcbuildlog_table} \
        WHERE detail_step_type like 'cCompilation' and document_url not like '';"
        result = self.select(sql) # <class 'generator'>
        row = next(result) # <class 'tuple'>
        return row
    
    def query_ccompilation_info(self, min_duration = 1.5):
        sql = f"select title, duration, document_url, signature \
        from {self.xcbuildlog_table} \
        where detail_step_type like 'cCompilation' and length(document_url) > 0 and duration >= {min_duration} \
        order by duration DESC"
        iterator = self.select(sql)
        datalist = list()
        for row in iterator:
            datalist.append({
                "title": row[0],
                "duration": row[1],
                "document_url": row[2],
            })
        return datalist
    
    def query_compilation_duration_with_target(self):
        sql = f"select replace(title,'Build target ','') as title, xcbtype, duration, warning_count \
        from {self.xcbuildlog_table} \
        where xcbtype in( 'target', 'main') order by duration  desc;"
        iterator = self.select(sql)
        datalist = list()
        for row in iterator:
            datalist.append({
                "title": row[0], 
                "xcbtype": row[1],
                "duration": row[2],
                "warning_count": row[3],
            })
        return datalist
    
    def query_targetids(self):
        sql = f"SELECT identifier FROM {self.xcbuildlog_table}  WHERE xcbtype in('target')"
        iterator = self.select(sql)
        targets = []
        for row in iterator:
            targets.append(row[0])
        return targets
    
    def export_target_data(self, targetid):
        sql = f"SELECT identifier, title, domain, xcbtype, detail_step_type, start_timestamp, end_timestamp, duration, compilation_duration, compilation_end_timestamp, signature, document_url FROM {self.xcbuildlog_table} where identifier like ? or parentid like ? ORDER BY start_timestamp ASC;"
        params = (targetid, targetid,)
        iterator = self.select(sql, params)
        datalist = list()
        for row in iterator:
            datalist.append({
                "identifier": row[0],
                "title": row[1],
                "domain": row[2],
                "xcbtype": row[3],
                "detail_step_type": row[4],
                "start_timestamp": row[5],
                "end_timestamp": row[6],
                "duration": row[7],
                "compilation_duration": row[8],
                "compilation_end_timestamp": row[9],
                "signature": row[10],
                "document_url": row[11],
            })
        return datalist
    
    def query_target_info(self):
        sql = f"SELECT replace(title, 'Build target ', '') AS title, identifier, xcbtype, duration, start_timestamp, end_timestamp, compilation_end_timestamp, compilation_duration FROM {self.xcbuildlog_table} WHERE xcbtype in('target', 'main') order by xcbtype, title;"
        iterator = self.select(sql)
        datalist = list()
        for row in iterator:
            datalist.append({
                "name": row[0], 
                "id": row[1],
                "type": row[2],
                "orig_duration": row[3],
                "orig_starttime": row[4],
                "orig_endtime": row[5],
                "orig_compile_endtime": row[6],
                "orig_compile_duration": row[7]
            })
        return datalist
    
    def statistic_buildtime_by_target(self, targetid):
        def query_compile_time():
            sql = f"SELECT min(start_timestamp), max(end_timestamp) FROM {self.xcbuildlog_table} WHERE parentid LIKE ? AND detail_step_type in ('cCompilation','swiftAggregatedCompilation')"
            params = (targetid,)
            iterator = self.select(sql, params)
            first_row = next(iterator)
            return first_row if first_row and first_row[0] else None
        
        def contain_swift_compile():
            sql = f"SELECT count(*) FROM {self.xcbuildlog_table} WHERE parentid LIKE ? AND detail_step_type like 'swiftAggregatedCompilation'"
            params = (targetid,)
            iterator = self.select(sql, params)
            row = next(iterator)
            if row and row[0]:
                return row[0] > 0
            else:
                return False
        
        def query_ccompile_starttime():
            sql = f"SELECT min(start_timestamp) FROM {self.xcbuildlog_table} WHERE parentid LIKE ? AND detail_step_type like 'cCompilation'"
            params = (targetid,)
            iterator = self.select(sql, params)
            row = next(iterator)
            return row[0] if row and row[0] else None
        
        def query_swift_compile_endtime(ccompile_starttime):
            sql = f"SELECT max(end_timestamp) FROM {self.xcbuildlog_table} WHERE parentid LIKE ? AND end_timestamp <= ?"
            params = (targetid, ccompile_starttime)
            iterator = self.select(sql, params)
            row = next(iterator)
            return row[0] if row and row[0] else None
        
        def calculate_compile_duration(starttime, endtime):
            if contain_swift_compile():
                ccompile_starttime = query_ccompile_starttime()
                swift_compile_endtime = query_swift_compile_endtime(ccompile_starttime)
                if ccompile_starttime and swift_compile_endtime:
                    compile_duration = (swift_compile_endtime - starttime) + (endtime - ccompile_starttime)
                    return compile_duration
            return endtime - starttime

        def query_before_compile_duration(compile_starttime):
            sql = f"SELECT sum(duration) FROM {self.xcbuildlog_table} WHERE parentid LIKE ? AND end_timestamp <= ?"
            params = (targetid, compile_starttime)
            iterator = self.select(sql, params)
            first_row = next(iterator)
            return first_row[0] if first_row and first_row[0] else 0
        
        def query_after_compile_duration(compile_endtime):
            sql = f"SELECT sum(duration) FROM {self.xcbuildlog_table} WHERE parentid LIKE ? AND start_timestamp >= ?"
            params = (targetid, compile_endtime)
            iterator = self.select(sql, params)
            first_row = next(iterator)
            return first_row[0] if first_row and first_row[0] else 0

        sql = f"SELECT min(start_timestamp) as start_timestamp, max(end_timestamp) as end_timestamp, sum(duration) as duration FROM {self.xcbuildlog_table} WHERE parentid LIKE ?"
        iterator = self.select(sql, (targetid,))
        first_row = next(iterator)
        if first_row and first_row[0]:
            buildinfo= dict()
            buildinfo["id"] = targetid
            buildinfo["build_starttime"] = first_row[0]
            buildinfo["build_endtime"] = first_row[1]
            buildinfo["sum_duration"] = first_row[2]
            buildinfo["include_compile"] = 0
            compile_time = query_compile_time()
            if compile_time:
                compile_starttime = compile_time[0]
                compile_endtime = compile_time[1]
                buildinfo["include_compile"] = 1
                buildinfo["compile_starttime"] = compile_starttime
                buildinfo["compile_endtime"] = compile_endtime
                buildinfo["compile_duration"] = calculate_compile_duration(compile_starttime, compile_endtime)
                buildinfo["before_compile_duration"] = query_before_compile_duration(compile_starttime)
                buildinfo["after_compile_duration"] = query_after_compile_duration(compile_endtime)
            return buildinfo
        else:
            return None
    
    def export_target_buildtime(self):
        def initialize_target_data(row, target_data):
            row["build_duration"] = target["orig_duration"]
            row["compile_duration"] = target["orig_compile_duration"]
            row["build_starttime"] = target["orig_starttime"]
            row["build_endtime"] = target["orig_endtime"]
            
        target_list = self.query_target_info()
        datalist = []
        for target in target_list:
            row = dict()
            row.update(target)
            targetname, xcbtype, original_duration = target["name"], target["type"], target["orig_duration"]
            if xcbtype == 'main' or targetname in ['Prepare build']:
                initialize_target_data(row, target)
                datalist.append(row)
                continue
            buildinfo = self.statistic_buildtime_by_target(target["id"])
            if not buildinfo:
                initialize_target_data(row, target)
                datalist.append(row)
                continue
            row.update(buildinfo)
            sum_duration = buildinfo["sum_duration"]
            if buildinfo["include_compile"]:
                pre_compile_duration = buildinfo["before_compile_duration"]
                after_compile_duration = buildinfo["after_compile_duration"]
                compile_duration = buildinfo["compile_duration"]
                build_duration = pre_compile_duration + compile_duration + after_compile_duration
                row["compile_duration"] = compile_duration
                row["build_duration"] = build_duration
            else:
                build_duration = buildinfo["build_endtime"] - buildinfo["build_starttime"]
                build_duration = build_duration if build_duration < sum_duration else sum_duration
                row["build_duration"] = build_duration
            datalist.append(row)
        return datalist
    
    def export_google_trace_data(self):
        sql = f"select title, start_timestamp, end_timestamp, duration, warning_count, xcbtype \
        from {self.xcbuildlog_table} \
        where xcbtype in ('target', 'main') \
        order by start_timestamp"
        result = self.select(sql)
        datalist = list()
        for row in result:
            cat = row[0].replace('Build target ', '')
            datalist.append({
                "name": cat, 
                "cat": cat,
                "ph": 'X',
                "ts": row[1] * 1000000,
                "dur": row[3] * 1000000,
                "pid": 1,
                "tid": row[0],
                "args": {
                    "title": row[0],
                    "startTimestamp": row[1],
                    "endTimestamp": row[2],
                    "duration": row[3],
                    "warningCount": row[4],
                    "xcbtype": row[5],
                }
                })
        return datalist