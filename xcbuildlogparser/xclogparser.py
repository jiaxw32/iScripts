import os
import argparse
import time
import threading
from threading import Timer,Thread
from plistlib import load, dump
import operator
import shutil
import ijson
from datetime import datetime, timezone, timedelta
from logmanifestmodel import LogManifestModel
from dbmanager import XCLogDBManager

script_dir = os.path.dirname(os.path.realpath(__file__))
post_action_logfile = os.path.join(script_dir, 'post-action.log')
workspace_dir = os.path.join(script_dir, 'data')
if not os.path.exists(workspace_dir):
    os.makedirs(workspace_dir)

def get_build_product_dir(file):
    f = open(file, "r")
    build_product_dir: str = f.read()
    build_product_dir = build_product_dir.strip()
    print(f'build product directory: {build_product_dir}')
    f.close()
    return build_product_dir

def get_mainfest_file(build_dir):
    # DerivedData path
    derived_data_dir = build_dir.replace('/Build/Products', '')
    # # Build Logs path
    build_log_dir = os.path.join(derived_data_dir, 'Logs/Build')
    # # LogStoreManifest.plist
    return os.path.join(build_log_dir, 'LogStoreManifest.plist')

def convert_to_unix_timestamp(timeinterval):
    reference_date = datetime(2001, 1, 1, tzinfo=timezone.utc)
    # delta = datetime.fromtimestamp(0) - datetime.utcfromtimestamp(0)
    locat_datetime = reference_date + timedelta(seconds=timeinterval)
    # s = locat_datetime.strftime('%Y-%m-%d %H:%M:%S')
    return datetime.timestamp(locat_datetime)

def parse_manifest_file(filename):
    with open(filename, 'rb') as fp:
        manifest = load(fp)
    log_dir = os.path.dirname(filename)
    logs = manifest["logs"]
    datalist= []
    
    for meta in logs.values():
        model = LogManifestModel()
        model.filename = meta["fileName"]
        model.filepath = os.path.join(log_dir, meta["fileName"])
        model.title = meta["title"]
        model.identifier = meta["uniqueIdentifier"]
        model.scheme = meta["schemeIdentifier-schemeName"]
        starttime = meta["timeStartedRecording"]
        endtime = meta["timeStoppedRecording"]
        model.duration = endtime - starttime
        model.begintime = convert_to_unix_timestamp(starttime)
        model.endtime = convert_to_unix_timestamp(endtime)
        model.classname = meta["className"]
        model.signature = meta["signature"]
        datalist.append(model)
    datalist.sort(key=lambda x: x.begintime, reverse=True)
    sorted_list = sorted(datalist, key=lambda x: x.begintime, reverse=True)
    return sorted_list

def parse_build_log(model):
    if os.path.exists(model.filepath):
        print(">>> xcactivitylog: " + model.filepath)
        taskid = model.identifier
        target_dir = os.path.join(workspace_dir, taskid)
        if not os.path.exists (target_dir):
            os.makedirs(target_dir)
        target_file = os.path.join(target_dir, model.filename)
        shutil.copy2(model.filepath, target_file)
        output_json_file = os.path.join(target_dir, f"{taskid}.json")
        os.system(f"xclogparser parse --file {target_file} --reporter flatJson > {output_json_file}")
        save_build_log_to_db(output_json_file)

def save_build_log_to_db(jsonfile):
    if not os.path.exists(jsonfile): return
    createtime = datetime.now().strftime('%Y%m%d_%H%M%S')
    tablename = f"build_log_{createtime}"
    XCLogDBManager.sharedinstance().create_buildlog_table(tablename)
    with open(jsonfile, 'rb') as input_file:
        jsonobj = ijson.items(input_file, 'item')
        build_item_list = (o for o in jsonobj)
        for item in build_item_list:
            XCLogDBManager.sharedinstance().save_build_log(item, tablename)
            print(f">>> insert <{item['identifier']}> record success.")

def tick():
    print(f"{datetime.now()} ******************** timer tick··· ********************")
    if os.path.exists(post_action_logfile):
        print(f'>>> find post build log file: {post_action_logfile}')
        # when the build task finished, xcode post-actions will output a post-action.log file
        build_product_dir = get_build_product_dir(post_action_logfile)
        # remove the postbuild.log file
        os.remove(post_action_logfile)
        manifest_file = get_mainfest_file(build_product_dir)
        if os.path.exists(manifest_file):
            print(f'>>> find manifest file: {manifest_file}')
            datalist = parse_manifest_file(manifest_file)
            if len(datalist) == 0: return
            model = datalist[0] # lastest task
            print(f"title={model.title}\nfile={model.filename}\nbegintime={model.begintime}\nendtime = {model.endtime}\nduration={model.duration}")
            if model.title.startswith("Build "): # the lastest taks is a build task
                parse_build_log(model)
            else: # other tasks, such as clean task
                print(f"not a build task: {model.title}")
        else:
            print(f">>> file {manifest_file}  doesn't exist")
    global timer
    timer = Timer(30, tick)
    timer.start()

if __name__ == "__main__":

    timer = Timer(1.0, tick)
    timer.start()