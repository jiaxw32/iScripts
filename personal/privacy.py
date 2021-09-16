import json
from random import random
import requests
from urllib.parse import unquote
import time

def get_headers_params():
    headers: dict = {}
    headers["accept"] = "*/*"
    headers["accept-encoding"] = "gzip, deflate, br"
    headers["accept-language"] = "zh-cn"
    headers["referer"] = "http://privacy.aiuys.com/?ref=@"
    headers["user-agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
    return headers

def query_privacy(text: str, callback = None):
    payload = {"value": text}
    url = f"http://privacy.aiuys.com/api/query?"
    try:
        response_data = requests.get(url, params=payload, headers = get_headers_params(), verify=False)
        if response_data.status_code == 200:
            # print(response_data.headers)
            if callback:
                callback(True, response_data.json(), "success")
        else:
            callback(False, None, response_data.reason)
    except:
        callback(False, None, 'exception occurred.')


if __name__ == "__main__":
    def req_success_callback(success: bool ,res: str, msg):
        if success:
            text = json.dumps(res, ensure_ascii = False, indent=4)
            print(text)
        else:
            print(msg)
    
    phone_nums = ["17600266607", "17777870871", "17600304179"]
    for item in phone_nums:
        time.sleep(2)
        query_privacy(item, callback=req_success_callback)

    # time.sleep(1.0)
    # qq_num = "xxx"
    # query_privacy(qq_num, callback=req_success_callback)

    # time.sleep(1.5)
    # email = "example-email@qq.com"
    # query_privacy(email, callback=req_success_callback)

    # time.sleep(2)
    # wb_userid = "@xxxx"
    # query_privacy(wb_userid, callback= req_success_callback)