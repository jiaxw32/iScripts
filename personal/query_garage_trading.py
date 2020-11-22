import sys
import requests
import random
from html.parser import HTMLParser
import html
from urllib.parse import unquote
from datetime import datetime

class MyHTMLParser(HTMLParser):
    def __init__(self, title):
        HTMLParser.__init__(self)
        self.house_codes = list()
        self.sale_status = list()
        self.title = title

    def handle_starttag(self, tag, attrs):
        if tag == 'img':
            for attr in attrs:
                if attr[0] == 'src':
                    src: str = attr[1]
                    status = src.replace('/images/', '').replace('.gif', '')
                    self.sale_status.append(status)

    def handle_data(self, data):
        if self.lasttag == 'a' and data:
            self.house_codes.append(data)
    
    def export_sale_info(self):
        saled_count = 0
        limit_count = 0
        onsale_count = 0
        total_count = len(self.house_codes)
        if total_count == len(self.sale_status):
            houses = list()
            for i in range(total_count):
                house_id = self.house_codes[i]
                status = self.sale_status[i].lower()
                if status == 'yel':
                    saled_count += 1
                elif status == 'green':
                    onsale_count += 1
                elif status == 'red':
                    limit_count += 1
                houses.append({"house_id": house_id, "status": status})
            print(f'\n{self.title}:\n总量: {total_count}\n已售: {saled_count}\n可售: {onsale_count}\n限制: {limit_count}')
            return houses
        else:
            return None

def get_headers_params():
    headers: dict = {}
    headers["Accept"] = "*/*"
    headers["Connection"] = "keep-alive"
    headers["Accept-Encoding"] = "gzip, deflate"
    headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.193 Safari/537.36"
    headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.8"
    headers["X-Requested-With"] = "XMLHttpRequest"
    headers["Origin"] = "http://zjj.sjz.gov.cn"
    # headers["Referer"] = "http://zjj.sjz.gov.cn/plus/scxx_subroom_show.php?sub=00&id=0130020182011"
    
    return headers;

def request_subroom_show(roomid = "0130020182011"):
    payload = {"sub": 0, "id": roomid}
    url = f"http://zjj.sjz.gov.cn/plus/scxx_subroom_show.php?"
    response_data = requests.get(url, params=payload, headers = get_headers_params(), verify=False)
    if response_data.status_code == 200:
        html = response_data.text
        return html
    else:
        print(f'request failed: {response_data.reason}')
    return None

def request_subroom_showx(roomid, subcode = "00"):
    numvar = random.random()
    url = f"http://zjj.sjz.gov.cn/plus/scxx_subroom_showx.php?sub={subcode}&id={roomid}&numvar={numvar}"
    response_data = requests.post(url, headers = get_headers_params(), verify=False)
    if response_data.status_code == 200:
        html = response_data.text
        return html
    else:
        print(f'request failed: {response_data.reason}')
    return None

if __name__ == "__main__":
    data = [{"blockid": "0130020182011", "subcode": "00", "title": "二区车库",}]
    
    current_date = datetime.now().strftime('%Y-%m-%d')
    print(f'当前日期：{current_date}')
    for item in data:
        response_text = request_subroom_showx(item["blockid"], item["subcode"])
        response_text = response_text.replace('+', ' ')
        html_text = unquote(response_text)
        if not html_text: continue
        parser = MyHTMLParser(item["title"])
        parser.feed(html_text)
        parser.export_sale_info()