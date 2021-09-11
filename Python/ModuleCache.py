import os
from datetime import datetime
import xlsxwriter
import collections
import hashlib
from pathlib import Path

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def create_workbook(filename):
    if os.path.exists(filename):
        os.remove(filename)
    workbook = xlsxwriter.Workbook(filename)
    return workbook

def create_worksheet(workbook, sheetname: str, headers: list):
    worksheet = workbook.add_worksheet(sheetname)
    cell_format = workbook.add_format()
    cell_format.set_bg_color('#BFBFBF') # 设置单元格背景色
    idx = 0
    for header in headers:
        title, width = header
        worksheet.write(0, idx, title, cell_format)
        worksheet.set_column(idx, idx, width)  # 设置列宽度
        idx += 1
    return worksheet

def export_modulefile(workdir: str, dstdir: str):
    # current date
    now = datetime.now()
    ts = datetime.timestamp(now)
    xlsxfile = os.path.join(dstdir, f"ModuleCache_{ts}.xlsx")
    if os.path.exists(xlsxfile):
        os.remove(xlsxfile)

    headers = [
        ('mainname', 50),
        ('filename', 55),
        ('dir', 15),
        ('filemd5', 36),
    ]
    workbook = create_workbook(xlsxfile)
    worksheet = create_worksheet(workbook, "moduel", headers)
    module_map = dict()
    row = 1
    for root, dirs, files in os.walk(workdir):
        for file in files:
            filename, file_ext = os.path.splitext(file)
            if file_ext == '.swiftmodule' or file_ext == '.pcm':
                module_file = os.path.join(root, file)
                filemd5 = md5(module_file)
                relpath = root.replace(workdir, '')
                paths = os.path.normpath(relpath).split(os.sep)

                worksheet.write(row, 0, filename)
                worksheet.write(row, 1, file)
                if len(paths) > 0 and paths[-1] != '.':
                    parentdir = paths[-1]
                    worksheet.write(row, 2, parentdir)
                    if file in module_map:
                        module_map[file].append(parentdir)
                    else:
                        module_map[file] = [parentdir]
                worksheet.write(row, 3, filemd5)
                row += 1
    
    # pcm 统计
    stat_headers = [
        ('hashcode', 50),
        ('pcmfile', 55),
        ('count', 15),
    ]
    worksheet = create_worksheet(workbook, "stat", stat_headers)
    ordered_dict = collections.OrderedDict(sorted(module_map.items()))
    row = 1
    for k, v in ordered_dict.items():
        if len(v) > 1: print(f"{k}({len(v)}): {v}\n")
        flag = 0
        for name in v:
            worksheet.write(row, 0, k)
            worksheet.write(row, 1, name)
            if flag == 0:
                worksheet.write(row, 2, len(v))
            flag += 1
            row += 1
    
    workbook.close()

if __name__ == "__main__":
    homedir = str(Path.home())
    srcdir = f"{homedir}/Library/Developer/Xcode/DerivedData/ModuleCache.noindex"
    dstdir = f"{homedir}/ModuleCache"

    if not os.path.exists(dstdir):
        os.makedirs(dstdir)

    export_modulefile(srcdir, dstdir)