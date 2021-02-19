import os
from databasemgr import WeChatDB
import jieba
from wordcloud import WordCloud, ImageColorGenerator
from PIL import Image
import numpy as np
from matplotlib import pyplot as plt
from datetime import datetime

# 微信表情
sugguest_words = (
    '捂脸', 
    '奸笑', 
    '强', 
    '呲牙', 
    '苦涩', 
    '庆祝', 
    '裂开', 
    '叹气', 
    '憨笑', 
    '旺柴', 
    '让我看看', 
    '吃瓜', 
    '烟花', 
    '爆竹', 
    '炸弹', 
    '发呆', 
    '悠闲', 
    '愉快', 
    '拥抱', 
    '睡',
    '破涕为笑',
    'Emm',
    '啤酒',
    '汗',
    '撇嘴',
    '偷笑',
    '流泪',
    '委屈',
    '奸笑',
    '666',
    '抱拳',
    )

def get_stopwords():
    f=open("./SupportFiles/stopwords.txt","r")
    stopwords={}.fromkeys(f.read().split("\n"))
    f.close()
    return stopwords

exclude_words = get_stopwords()

def generate_wordcloud_image(fname, msglist, enable_mask = False):
    cloud_words = []

    global exclude_words
    global sugguest_words
    jieba.suggest_freq(sugguest_words, tune = True)

    for msg in msglist:
        words = list(jieba.cut(msg, HMM = False))
        for word in words:
            if (word not in exclude_words) and len(word) > 1:
                # if 'iO' in word:
                #     print(f"### {word}")
                cloud_words.append(word.strip())
    msg_text=",".join(cloud_words)

    wc: WordCloud = None
    font_file = "./SupportFiles/simsun.ttf"
    if enable_mask:
        cloud_mask = np.array(Image.open("./SupportFiles/heart.jpg"))
        wc = WordCloud(mask=cloud_mask, background_color="white", max_words=200, font_path=font_file)
    else:
        wc = WordCloud(
            background_color="white",
            max_words=200,
            font_path=font_file,
            width=800,
            height=600,
        )
    wc.collocations = False

    # with open("./words.txt", "w") as text_file:
    #     text_file.write(msg_text)

    wc.generate(msg_text)

    now = datetime.now()
    timestamp = int(datetime.timestamp(now))
    imagedir = "./images" 
    if not os.path.exists(imagedir):
        os.makedirs(imagedir)
    output_file = f"{imagedir}/{fname}_{timestamp}.png"
    wc.to_file(output_file)
    # print(wc.words_)
    print(f'export cloud image {output_file} success.')

if __name__ == '__main__':
    
    db = WeChatDB(filename="./sqlitedb/message_4.sqlite")
    msglist = db.query_group_chat_msg('Chat_tech')
    generate_wordcloud_image('tech', msglist)

    # msglist = db.query_personal_chat_msg('Chat_cy')
    # generate_wordcloud_image('cy_heart_my', msglist, True)
    
    db.close()