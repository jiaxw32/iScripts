import json
import os
import shutil
import xlsxwriter
from xlsxwriter import workbook
from xlsxwriter import worksheet

def create_workbook(filename):
    if os.path.exists(filename):
        os.remove(filename)
    workbook = xlsxwriter.Workbook(filename)
    return workbook

def create_worksheet(workbook):
    worksheet = workbook.add_worksheet('darkimage')
    cell_format = workbook.add_format()
    cell_format.set_bg_color('#BFBFBF') # 设置单元格背景色
    headers = [
        ('pod', 23),
        ('filename', 60),
        ('filepath', 200),
        ('filesize', 12),
        ('scale', 10)
    ]
    idx = 0
    for header in headers:
        title, width = header
        worksheet.write(0, idx, title, cell_format)
        worksheet.set_column(idx, idx, width)  # 设置列宽度
        idx += 1
    return worksheet

def search_dark_imagefile(wbdir: str, callback = None):
    cnt = 0
    for root, dirs, files in os.walk(wbdir):
        for file in files:
            filename, file_extension = os.path.splitext(file)
            if file_extension == '.json' and filename == 'Contents' and not dirs:
                contents_file = os.path.join(root, file)
                paths = os.path.normpath(root.replace(wbdir, '')).split(os.sep)
                pod = paths[1]
                with open(contents_file) as json_file:
                    data = json.load(json_file)
                    if 'images' in data:
                        for image in data['images']:
                            if ('appearances' not in image) or ('filename' not in image):
                                continue
                            appearances = image['appearances']
                            imagename = image['filename']
                            scale = image.get('scale', 'unkonw')
                            for obj in appearances:
                                if 'value' not in obj:
                                    continue
                                mode = obj['value']
                                if mode == 'dark':
                                    imagefile = os.path.join(root, imagename) 
                                    cnt += 1
                                    callback(cnt, pod, imagefile, scale)


if __name__ == "__main__":
    wbdir = "/Users/admin/iproject"
    destdir = "/Users/admin/darkimage"

    if not os.path.exists(destdir):
        os.makedirs(destdir)

    xlsxfile = os.path.join(destdir, 'darkimage.xlsx')
    workbook = create_workbook(xlsxfile)
    worksheet = create_worksheet(workbook)

    def search_darkimage_handler(row: int, pod: str, imagefile: str, scale: str):
        imagename = os.path.basename(imagefile)        
        imagesize = os.path.getsize(imagefile)
        subpath = imagefile[len(wbdir):]
        # insert row data
        worksheet.write(row, 0, pod)
        worksheet.write(row, 1, imagename)
        worksheet.write(row, 2, subpath)
        worksheet.write_number(row, 3, imagesize)
        worksheet.write(row, 4, scale)
        # copy image to dest dir
        dstdir = os.path.join(destdir, pod)
        if not os.path.exists(dstdir):
            os.makedirs(dstdir)
        shutil.copy2(imagefile, dstdir)
    
    search_dark_imagefile(wbdir, callback=search_darkimage_handler)

    workbook.close()