import re
import requests
import logging
from collections import OrderedDict
from datetime import datetime
import litecon
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.FileHandler("function.log", "w", encoding="utf-8"), logging.StreamHandler()])

timeout = 3

def parse_template(template_file):
    logging.info(f"开始解析模板文件: {template_file}")
    template_channels = OrderedDict()
    current_category = None

    with open(template_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if "#genre#" in line:
                    current_category = line.split(",")[0].strip()
                    template_channels[current_category] = []
                elif current_category:
                    channel_name = line.split(",")[0].strip()
                    template_channels[current_category].append(channel_name)

    logging.info(f"模板文件解析完成: {template_file}")
    return template_channels

def parse_corrections(correction_file):
    logging.info(f"开始解析修正文件: {correction_file}")
    corrections = {}

    with open(correction_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(",")
                unified_name = parts[0].strip()
                for alias in parts[1:]:
                    corrections[alias.strip()] = unified_name

    logging.info(f"修正文件解析完成: {correction_file}")
    return corrections

def fetch_channels(url, corrections):
    logging.info(f"开始获取频道: {url}")
    channels = OrderedDict()

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        response.encoding = 'utf-8'
        lines = response.text.split("\n")
        current_category = None
        is_m3u = any("#EXTINF" in line for line in lines[:15])
        source_type = "m3u" if is_m3u else "txt"
        logging.info(f"url: {url} 获取成功，判断为{source_type}格式")

        if is_m3u:
            for line in lines:
                line = line.strip()
                if line.startswith("#EXTINF"):
                    match = re.search(r'group-title="(.*?)",(.*)', line)
                    if match:
                        current_category = match.group(1).strip()
                        channel_name = match.group(2).strip()
                        channel_name = corrections.get(channel_name, channel_name)
                        if current_category not in channels:
                            channels[current_category] = []
                elif line and not line.startswith("#"):
                    channel_url = line.strip()
                    if current_category and channel_name:
                        channels[current_category].append((channel_name, channel_url))
        else:
            for line in lines:
                line = line.strip()
                if "#genre#" in line:
                    current_category = line.split(",")[0].strip()
                    channels[current_category] = []
                elif current_category:
                    match = re.match(r"^(.*?),(.*?)$", line)
                    if match:
                        channel_name = match.group(1).strip()
                        channel_url = match.group(2).strip()
                        channel_name = corrections.get(channel_name, channel_name)
                        channels[current_category].append((channel_name, channel_url))
                    elif line:
                        channel_name = line.strip()
                        channel_name = corrections.get(channel_name, channel_name)
                        channels[current_category].append((channel_name, ''))
        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"url: {url} 爬取成功✅，包含频道分类: {categories}")
    except requests.exceptions.Timeout:
        logging.warning(f"url: {url} 请求超时，跳过该链接")
    except requests.RequestException as e:
        logging.error(f"url: {url} 爬取失败❌, Error: {e}")

    return channels

def match_channels(template_channels, all_channels):
    logging.info("开始匹配频道")
    matched_channels = OrderedDict()

    for category, channel_list in template_channels.items():
        matched_channels[category] = OrderedDict()
        for channel_name in channel_list:
            for online_category, online_channel_list in all_channels.items():
                for online_channel_name, online_channel_url in online_channel_list:
                    if channel_name == online_channel_name:
                        if channel_name not in matched_channels[category]:
                            matched_channels[category][channel_name] = []
                        if online_channel_url not in [url for _, url in matched_channels[category][channel_name]]:
                            matched_channels[category][channel_name].append((online_channel_name, online_channel_url))

    logging.info("频道匹配完成")
    return matched_channels

def filter_source_urls(template_file, correction_file):
    logging.info("开始过滤源URL")
    template_channels = parse_template(template_file)
    corrections = parse_corrections(correction_file)
    source_urls = litecon.source_urls

    all_channels = OrderedDict()
    for url in source_urls:
        fetched_channels = fetch_channels(url, corrections)
        for category, channel_list in fetched_channels.items():
            if category in all_channels:
                all_channels[category].extend(channel_list)
            else:
                all_channels[category] = channel_list

    matched_channels = match_channels(template_channels, all_channels)
    logging.info("源URL过滤完成")
    return matched_channels, template_channels

def is_ipv6(url):
    return re.match(r'^http:\/\/\[[0-9a-fA-F:]+\]', url) is not None

def clean_url(url):
    return url.split('$')[0]

def append_to_blacklist(file, line):
    clean_line = f"{line.split(',')[0]},{clean_url(line.split(',')[1])}\n"
    logging.info(f"添加到黑名单: {clean_line.strip()}")
    with open(file, 'a', encoding='utf-8') as f:
        f.write(clean_line)

def append_to_whitelist(file, line):
    clean_line = f"{line.split(',')[0]},{clean_url(line.split(',')[1])}\n"
    logging.info(f"添加到白名单: {clean_line.strip()}")
    with open(file, 'a', encoding='utf-8') as f:
        f.write(clean_line)

def remove_duplicates(file):
    logging.info(f"去重文件: {file}")
    with open(file, 'r', encoding='utf-8') as f):
        lines = f.readlines()
    unique_lines = list(OrderedDict.fromkeys(lines))
    with open(file, 'w', encoding='utf-8') as f):
        f.writelines(unique_lines)

def remove_empty_lines(file):
    logging.info(f"删除空行: {file}")
    with open(file, 'r', encoding='utf-8') as f):
        lines = f.readlines()
    non_empty_lines = [line for line in lines if line.strip()]
    with open(file, 'w', encoding='utf-8') as f):
        f.writelines(non_empty_lines)

def check_urls(urls):
    logging.info("开始检查URL")
    blacklist = set()
    whitelist = set()
    try:
        with open('blacklist.txt', 'r', encoding='utf-8') as file:
            blacklist = set(clean_url(line.strip().split(',')[1]) for line in file.readlines() if line.strip())
    except IOError:
        pass  # 如果文件不存在则忽略

    try:
        with open('whitelist.txt', 'r', encoding='utf-8') as file:
            whitelist = set(clean_url(line.strip().split(',')[1]) for line in file.readlines() if line.strip())
    except IOError:
        pass  # 如果文件不存在则忽略

    valid_urls = []
    for name, url in urls:
        cleaned_url = clean_url(url)
        if cleaned_url in blacklist:
            logging.info(f"URL在黑名单中: {name}, {cleaned_url}")
            continue
        if cleaned_url in whitelist:
            logging.info(f"URL在白名单中: {name}, {cleaned_url}")
            valid_urls.append((name, cleaned_url))
            continue

        try:
            if "://" in cleaned_url:
                start_time = time.time()
                response = requests.get(cleaned_url, timeout=timeout, stream=True)
                elapsed_time = (time.time() - start_time) * 1000
                if response.status_code == 200:
                    logging.info(f'检测正常: {name}, {cleaned_url}, 响应时间: {elapsed_time:.2f}ms')
                    valid_urls.append((name, cleaned_url))
                    append_to_whitelist('whitelist.txt', f'{name},{cleaned_url}\n')
                else:
                    logging.warning(f'检测失败: {name}, {cleaned_url}')
                    append_to_blacklist('blacklist.txt', f'{name},{cleaned_url}\n')
        except requests.exceptions.Timeout:
            logging.warning(f'超时错误: {name}, {cleaned_url}，将该链接添加到黑名单')
            append_to_blacklist('blacklist.txt', f'{name},{cleaned_url}\n')
            continue
        except requests.exceptions.RequestException as e:
            logging.warning(f'其他错误: {name}, {cleaned_url}, Error: {e}')
            append_to_blacklist('blacklist.txt', f'{name},{cleaned_url}\n')

    remove_duplicates('blacklist.txt')
    remove_duplicates('whitelist.txt')
    remove_empty_lines('blacklist.txt')
    remove_empty_lines('whitelist.txt')

    logging.info("URL检查完成")
    return valid_urls

def updateChannelUrlsM3U(channels, template_channels):
    logging.info("开始更新频道URL到M3U文件")
    written_urls = set()

    current_date = datetime.now().strftime("%Y-%m-%d")
    for group in litecon.announcements:
        for announcement in group['entries']:
            if announcement['name'] is None:
                announcement['name'] = current_date

    with open("litelive.m3u", "w", encoding="utf-8") as f_m3u:
        f_m3u.write(f"""#EXTM3U x-tvg-url={",".join(f'"{epg_url}"' for epg_url in litecon.epg_urls)}\n""")

        with open("litelive.txt", "w", encoding="utf-8") as f_txt:
            for group in litecon.announcements:
                f_txt.write(f"{group['channel']},#genre#\n")
                for announcement in group['entries']:
                    f_m3u.write(f"""#EXTINF:-1 tvg-id="1" tvg-name="{announcement['name']}" tvg-logo="{announcement['logo']}" group-title="{group['channel']}",{announcement['name']}\n""")
                    f_m3u.write(f"{announcement['url']}\n")
                    f_txt.write(f"{announcement['name']},{announcement['url']}\n")

            for category, channel_list in template_channels.items():
                f_txt.write(f"{category},#genre#\n")
                if category in channels:
                    for channel_name in channel_list:
                        if channel_name in channels[category]:
                            # 去重逻辑
                            unique_urls = list(OrderedDict.fromkeys([url for _, url in channels[category][channel_name]]))
                            sorted_urls = sorted(unique_urls, key=lambda url: not is_ipv6(url) if litecon.ip_version_priority == "ipv6" else is_ipv6(url))
                            filtered_urls = check_urls([(channel_name, url) for url in sorted_urls if not is_ipv6(url) and url not in written_urls and not any(blacklist in url for blacklist in litecon.url_blacklist)])

                            # 保证数字连续
                            index = 1
                            for name, url in filtered_urls:
                                url_suffix = f"$雷蒙影视•IPV4" if len(filtered_urls) == 1 else f"$雷蒙影视•IPV4『线路{index}』"
                                if '$' in url:
                                    base_url = clean_url(url)
                                else:
                                    base_url = url

                                new_url = f"{base_url}{url_suffix}"

                                if base_url not in written_urls:
                                    f_m3u.write(f"#EXTINF:-1 tvg-id=\"{index}\" tvg-name=\"{channel_name}\" tvg-logo=\"https://gitee.com/yuanzl77/TVBox-logo/raw/main/png/{channel_name}.png\" group-title=\"{category}\",{channel_name}\n")
                                    f_m3u.write(new_url + "\n")
                                    f_txt.write(f"{channel_name},{new_url}\n")
                                    written_urls.add(base_url)
                                    index += 1

            f_txt.write("\n")

    logging.info("频道URL更新完成")

if __name__ == "__main__":
    template_file = "litedemo.txt"
    correction_file = "correction.txt"
    logging.info("开始过滤源URL和匹配模板")
    channels, template_channels = filter_source_urls(template_file, correction_file)
    logging.info("过滤源URL和匹配模板完成")
    logging.info("开始更新M3U和TXT文件")
    updateChannelUrlsM3U(channels, template_channels)
    logging.info("更新M3U和TXT文件完成")
