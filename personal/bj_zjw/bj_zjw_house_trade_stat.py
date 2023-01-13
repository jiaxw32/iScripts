import os
import requests
from urllib.parse import unquote
from datetime import datetime
from bs4 import BeautifulSoup
from database import HouseTradeStatDBManager

keys = ["online_sign_count", "online_sign_area", "house_sign_count", "house_sign_area"]

def month_signing_stat_handler(success: bool, data: str):

    def parse_agent_content(element, complete_handler = None):
        '''
        统计经纪机构成交数据
        '''
        tr_list = element.table.tbody.find_all("tr")
        agent_list = []
        for tr_item in tr_list:
            td_list = tr_item.find_all("td")
            if len(td_list) >= 4:
                company = td_list[1].text
                sign_in_count = td_list[2].text
                sign_out_count = td_list[3].text
                agent_list.append((company, sign_in_count, sign_out_count))
        if complete_handler:
            complete_handler(agent_list)
        else:
            for item in agent_list: print(item)

    def parse_month_content(element, complete_handler = None):
        '''
        按区县或建筑面积统计成交数据
        '''
        title_list = [] # 标题
        count_list = [] # 交易数量
        area_list = [] # 成交面积

        thead_list = element.find_all("thead")
        for thead_item in thead_list:
            th_list = thead_item.tr.find_all("th")
            if len(th_list) > 1:
                for idx in range(1, len(th_list)):
                    title_list.append(th_list[idx].text)

        tbody_list = element.find_all("tbody")
        for tbody_item in tbody_list:
            tr_list = tbody_item.find_all("tr")
            if len(tr_list) >= 2:
                tr_deal_count = tr_list[0] # 套数
                for item in tr_deal_count.find_all("td"):
                    count_list.append(item.text)

                tr_deal_area = tr_list[1] # 面积
                for item in tr_deal_area.find_all("td"):
                    area_list.append(item.text)
    
        if complete_handler:
            complete_handler(title_list, count_list, area_list)
        else:
            print("\n")
            for idx in range(0, len(title_list)):
                print(f"{title_list[idx]}\t{count_list[idx]}\t{area_list[idx]}")
    
    if success == True:
        soup = BeautifulSoup(data, "html.parser")

        header =  soup.find("div", class_ = "month_header").h3.text
        header_more = soup.find("div", class_ = "month_header_more").a.text
        print(f"{header} {header_more}")

        # 按经纪机构统计签约、退房数量
        agent_company_box = soup.find("div", class_ = "month_jjjg_box")
        if agent_company_box is not None:
            parse_agent_content(agent_company_box)
        
        month_content_list = soup.find_all("div", class_ = "month_content")
        if len(month_content_list) >= 3:
            # 按在区县统计成交量、面积
            county_box_element = month_content_list[1]
            parse_month_content(county_box_element)

            # 按建筑面积统计成交数量、面积
            area_box_element = month_content_list[2]
            parse_month_content(area_box_element)
    else:
        print(data)

def day_signing_stat_handler(success: bool, data: str):
    if success == True:
        soup = BeautifulSoup(data, "html.parser")
        title =  soup.head.title.text
        print(title, "\n")

        statistics_content = soup.find('div', class_ = "statistics_content") # class 'bs4.element.Tag'
        div_list = statistics_content.find_all('div')
        for i in range(0, len(div_list)):
            div_item = div_list[i]
            text = div_item.h3.text
            print(text)

            data = dict()
            data["title"] = text
            data["trade_date"] = ""
            idx = text.find("存量房网上签约")
            if idx != -1:
                data["trade_date"] = text[: idx]
            
            tr_list = div_item.table.find_all("tr")
            for idx in range(0, len(tr_list)):
                tr_item = tr_list[idx]
                td_title: str = tr_item.find("td").text.strip()
                td_value: str = tr_item.find("td", class_ = "r").text.strip()
                print(f"{td_title}{td_value}")

                global keys
                if idx == 0 or idx == 2: # 签约数量
                    data[keys[idx]] = int(td_value)
                elif idx == 1 or idx == 3: # 签约面积
                    data[keys[idx]] = float(td_value)
            
            global g_dbmgr
            g_dbmgr.save_trade_data(data)
            print("\n")
    else:
        print(data)


def send_request(pageid: str, complete_handler = None):
    url = f"http://bjjs.zjw.beijing.gov.cn/eportal/ui?"

    headers: dict = {}
    headers["Connection"] = "keep-alive"
    headers["Upgrade-Insecure-Requests"] = "1"
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    headers["User-Agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1"
    headers["Referer"] = "http://zjw.beijing.gov.cn/bjjs/fwgl/clfjyfwpt/index.shtml"
    headers["Accept-Language"] = "zh-cn"
    headers["Accept-Encoding"] = "gzip, deflate"

    payload = {"pageId": pageid}

    response_data = requests.get(url, params=payload, headers = headers, verify=False)
    if response_data.status_code == 200:
        html = response_data.text
        if complete_handler is not None:
            complete_handler(True, html)
        else:
            print(html)
    else:
        error_msg = f'request failed: {response_data.reason}'
        if complete_handler:
            complete_handler(False, error_msg)
        else:
            print(error_msg)

if __name__ == "__main__":

    workdir = os.path.dirname(os.path.realpath(__file__))
    dbpath = f"{workdir}/house_trade_stat.db"
    g_dbmgr = HouseTradeStatDBManager(dbpath)

    send_request(pageid=53610668, complete_handler= day_signing_stat_handler)
    send_request(pageid=53610670, complete_handler=month_signing_stat_handler)
    
    g_dbmgr.close()