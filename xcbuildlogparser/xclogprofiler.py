import json
import sys
import os
import csv
from DatabaseManager import XCLogDBManager
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt

class XCLogProfiler(object):
    def __init__(self, dbfile):
        self._dbfile = dbfile
        self._dbmanager = XCLogDBManager(dbfile)
    
    @property
    def dbmanager(self):
        return self._dbmanager
    
    def builddata_dir(self):
        return os.path.dirname(self._dbfile)
    
    def count_ccompilation_info(self):
        info = self.dbmanager.count_ccompilation_duration()
        filecount = info[1]
        ccompilation_duration = info[0]
        print(f'total c compilation duration: {ccompilation_duration}, file count: {filecount}.')
        
    def export_all_targets2chromtrace(self):

        def export_targetdata2chrometrace(targetdata, targetname):
            targetname = targetname.replace(' ', '_')
            filename = os.path.join(self.builddata_dir(), f'{targetname}.json')
            datalist = list()
            for item in targetdata:
                identifier: str = item["identifier"]
                tid = identifier.split('_')[-1]
                detail_type = item["detail_step_type"]
                datalist.append({
                    "name": item["title"], 
                    "cat": detail_type,
                    "ph": 'X',
                    "ts": item["start_timestamp"] * 1000000,
                    "dur": item["duration"] * 1000000,
                    "pid": 1,
                    "tid": f"{tid}-{detail_type}",
                    "args": item
                })

            with open(filename, 'w') as outfile:
                json.dump(datalist, outfile)
                print(f">>> export chrome tracing {filename} file finished.")

        targets = self.dbmanager.query_target_info()
        for item in targets:
            targetid = item["id"]
            name = item["name"]
            if item["type"] == 'main': name = 'main'
            datalist = self.dbmanager.export_target_data(targetid)
            export_targetdata2chrometrace(datalist, name)
    
    def export_all_target2csv(self):
        
        def export_targetdata2csv(targetdata, targetname: str):
            targetname = targetname.replace(' ', '_')
            filename = os.path.join(self.builddata_dir(), f"{targetname}.csv")
            with open(filename, mode='w') as csv_file:
                fieldnames = ['identifier', 'title', 'domain', 'xcbtype', 'detail_step_type', 'start_timestamp', 'end_timestamp', 'duration', 'compilation_duration', 'compilation_end_timestamp', 'signature', 'document_url']
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for item in targetdata:
                    writer.writerow(item)
                print(f"export {filename} success.")
        
        targets = self.dbmanager.query_target_info()
        for item in targets:
            targetid = item["id"]
            name = item["name"]
            if item["type"] == 'main': name = 'main'
            datalist = self.dbmanager.export_target_data(targetid)
            export_targetdata2csv(datalist, name)
    
    def export_target_buildtime(self):
        def export_target_buildtime2csv(datalist):
            filename = os.path.join(self.builddata_dir(), f'target_buildtime.csv')
            with open(filename, mode='w') as csv_file:
                fieldnames = ['name', 'id', 'type', 'orig_starttime', 'orig_endtime', 'build_starttime', 'build_endtime', 'orig_compile_endtime', 'include_compile', 'compile_starttime', 'compile_endtime', 'orig_duration', 'orig_compile_duration', 'sum_duration', 'build_duration', 'compile_duration', 'before_compile_duration', 'after_compile_duration']
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for data in datalist:
                    writer.writerow(data)
                print(f"export {filename} success.")
        
        def export_target_buildtime2chromtrace(datalist):
            filename = os.path.join(self.builddata_dir(), f'target_buildtime.json')
            arr = list()
            for item in datalist:
                identifier: str = item["id"]
                tid = identifier.split('_')[-1]
                if "include_compile" not in item or not item["include_compile"]:
                    continue
                duration =  item["compile_endtime"] - item["compile_starttime"]
                arr.append({
                    "name": item["name"],
                    "cat": item["type"],
                    "ph": 'X',
                    "ts": item["compile_starttime"] * 1000000,
                    "dur": duration * 1000000,
                    "pid": 1,
                    "tid": item["name"],
                    "args": item
                })

            with open(filename, 'w') as outfile:
                json.dump(arr, outfile)
                print(f">>> export chrome tracing {filename} file finished.")

        datalist = self.dbmanager.export_target_buildtime()
        export_target_buildtime2csv(datalist)
        export_target_buildtime2chromtrace(datalist)
        
    
    def export_compilation_duration_barchart(self):
        datalist = self.dbmanager.query_compilation_duration_with_target()
        
        durations = list()
        targets = list()
        for item in datalist:
            durations.append(item["duration"])
            targets.append(item["title"])
        y_pos = np.arange(len(durations))

        # 竖状条形图
        # plt.bar(y_pos, durations, align='center', alpha=0.5)
        # plt.xticks(y_pos, targets)
        # plt.ylabel('duration(s)')
        # plt.title('Compilation duration of target')

        # 横状条形图
        plt.barh(y_pos, durations, align='center', alpha=0.5)
        plt.yticks(y_pos, targets)
        plt.xlabel('duration(s)')
        plt.title('Compilation duration of target')
        plt.show()

if __name__ == '__main__':
    dbfile = "/Users/a58/58_ios_libs/XCBuildLogParser/data2/9692138A-28DC-4118-A57D-F45CBFC3BBB7/xcbuildlog.db"
    profiler = XCLogProfiler(dbfile)
    profiler.export_target_buildtime()
