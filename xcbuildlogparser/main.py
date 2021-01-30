import os
import time
import threading
from threading import Timer,Thread
from datetime import datetime
from xclogparser import XCLogParser
from xclogprofiler import XCLogProfiler

# current script directory
script_dir = os.path.dirname(os.path.realpath(__file__))
# make workspace directory if not exist.
workspace_dir = os.path.join(script_dir, 'data')
if not os.path.exists(workspace_dir):
    os.makedirs(workspace_dir)
# post action log file
post_action_logfile = os.path.join(script_dir, 'post-action.log')

def get_build_dir(file):
    f = open(file, "r")
    build_dir: str = f.read()
    build_dir = build_dir.strip()
    print(f'build product directory: {build_dir}')
    f.close()
    return build_dir

def parse_finish_callback(dbfile: str):
    if not dbfile: return
    print(f"xcbuild log db file: {dbfile}")
    profiler = XCLogProfiler(dbfile)
    profiler.export_target_buildtime()
    profiler.export_all_target2csv()
    profiler.export_all_targets2chromtrace()

def tick():
    print(f"{datetime.now()} ******************** timer tick··· ********************")
    if os.path.exists(post_action_logfile):
        print(f'>>> find post build log file: {post_action_logfile}')
        # when the build task finished, xcode post-actions script will output a post-action.log file
        build_product_dir = get_build_dir(post_action_logfile)
        # remove the postbuild.log file
        os.remove(post_action_logfile)
        # get LogStoreManifest.plist file, usually located in ~/Library/Developer/Xcode/DerivedData/{project_dir}/Logs/Build/LogStoreManifest.plist.
        manifest_file = XCLogParser.get_manifest_file(build_product_dir)
        if manifest_file and os.path.exists(manifest_file):
            print(f'>>> find manifest file: {manifest_file}')
            datalist = XCLogParser.parse_manifest_file(manifest_file)
            if len(datalist) == 0: return
            model = datalist[0] # lastest task
            print(f"title={model.title}\nfile={model.filename}\nbegintime={model.begintime}\nendtime = {model.endtime}\nduration={model.duration}")
            if model.title.startswith("Build "): # the lastest taks is a build task
                XCLogParser.copy_and_parse_xclogfile(model, workspace_dir, parse_finish_callback)
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