import os
import time
import shutil
import ijson
import json
from plistlib import load, dump
import operator
import shutil
import uuid
from LogManifestModel import LogManifestModel
from DatabaseManager import XCLogDBManager
from xclogprofiler import XCLogProfiler

script_dir = os.path.dirname(os.path.realpath(__file__))
xclogparser_tool = os.path.join(script_dir, 'tools/xclogparser')

class XCLogParser(object):

    @staticmethod
    def get_manifest_file(build_dir: str):
        idx = build_dir.rfind('/Build/Products')
        if idx == -1: return None
        # DerivedData path
        derived_data_dir = build_dir[:idx]
        # Build Logs path
        build_log_dir = os.path.join(derived_data_dir, 'Logs/Build')
        # LogStoreManifest.plist
        return os.path.join(build_log_dir, 'LogStoreManifest.plist')

    @staticmethod
    def parse_manifest_file(file):
        with open(file, 'rb') as fp:
            manifest = load(fp)
            log_dir = os.path.dirname(file)
            datalist= list()
            for meta in manifest["logs"].values():
                model = LogManifestModel.model_with_dic(meta)
                model.filepath = os.path.join(log_dir, model.filename)
                datalist.append(model)
            datalist.sort(key=lambda x: x.begintime, reverse=True)
            sorted_list = sorted(datalist, key=lambda x: x.begintime, reverse=True)
            return sorted_list

    @staticmethod
    def copy_and_parse_xclogfile(model: LogManifestModel, destdir, finish_callback = None):
        srcfile = model.filepath
        dest_logfile = XCLogParser.copy_xclogfile(srcfile, destdir)
        flatjson_file = XCLogParser.parse_xclogfile(dest_logfile)
        XCLogParser.convert_flatjson2db(flatjson_file, model, finish_callback)

    @staticmethod
    def copy_xclogfile(srcfile, destdir):
        if not os.path.exists(srcfile):
            print(f"copy xclog file failed, {srcfile} not exist.")
            return
        print(">>> xcactivitylog: " + srcfile)
        filename = os.path.basename(srcfile)
        filename_without_ext = os.path.splitext(filename)[0]
        destdir = os.path.join(destdir, filename_without_ext)
        if not os.path.exists (destdir):
            os.makedirs(destdir)
        logfile = os.path.join(destdir, filename)
        shutil.copy2(srcfile, logfile)
        return logfile

    @staticmethod
    def parse_xclogfile(logfile):
        if not os.path.exists(logfile):
            print(f"parse xclog file failed, {logfile} not exist.")
            return
        path, fllename = os.path.split(logfile)
        mainfilename = os.path.splitext(fllename)[0]
        output_jsonfile = os.path.join(path, f"{mainfilename}.json")
        # run xclogparser tool to parse xcactivitylog and convert to flatjson file.
        print(f'xclogparser tool: {xclogparser_tool}')
        os.system(f"{xclogparser_tool} parse --file {logfile} --reporter flatJson > {output_jsonfile}")
        return output_jsonfile

    @staticmethod
    def convert_flatjson2db(jsonfile, model: LogManifestModel = None, finish_callback = None):
        if not os.path.exists(jsonfile):
            print(f"convert flatjson to sqlite db failed, {jsonfile} file not exist.")
            return
        dbfile = os.path.join(os.path.dirname(jsonfile), "xcbuildlog.db")
        dbmanager = XCLogDBManager(dbfile)
        if model:
            rowid = str(uuid.uuid4())
            params = (rowid, model.identifier, model.title, model.filename, model.filepath, model.scheme, model.begintime, model.endtime, model.duration, model.signature, model.classname, model.original_logs)
            dbmanager.save_buildlog_metadata(params)
        cnt = 0
        with open(jsonfile, 'rb') as input_file:
            jsonobj = ijson.items(input_file, 'item')
            build_item_list = (o for o in jsonobj)
            for item in build_item_list:
                dbmanager.save_build_log(item)
                cnt += 1
                print(f">>> insert <{item['identifier']}> record success.")
        print(f"insert total count: {cnt}")
        
        # the insert operation is async, so wait until the database quene hasn't insert tasks.
        size = dbmanager.get_tasksize()
        while size > 0:
            print(f"database queue task left: {size}")
            time.sleep(1.5)
            size = dbmanager.get_tasksize()
        dbmanager.close()
        # parse finish callback
        if finish_callback: finish_callback(dbfile)

if __name__ == '__main__':
    def parse_finish_callback(dbfile: str):
        if not dbfile: return
        print(f"xcbuild log db file: {dbfile}")
        profiler = XCLogProfiler(dbfile)
        profiler.export_target_buildtime()
        profiler.export_all_target2csv()
        profiler.export_all_targets2chromtrace()
    
    xclogfile = "./data2/01D6286A-AB7A-4235-B02C-794D01FD25A2/01D6286A-AB7A-4235-B02C-794D01FD25A2.xcactivitylog"
    flatjsonfile = XCLogParser.parse_xclogfile(xclogfile)
    XCLogParser.convert_flatjson2db(flatjsonfile, finish_callback=parse_finish_callback)