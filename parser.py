import argparse
import json
import os
import re
from collections import defaultdict, Counter
from pathlib import Path

parser = argparse.ArgumentParser(description='The process of analyzing the logfiles')
parser.add_argument('-f', dest='file', action='store', help='Path to logfile or logfiles')
args = parser.parse_args()


def path_type():
    if os.path.isdir(args.file):
        files = filter(lambda x: x.endswith('.log'), os.listdir(args.file))
        logfiles = []
        for file in list(files):
            file = Path().joinpath(args.file).joinpath(file)
            logfiles.append(file)
        return logfiles
    elif os.path.isfile(args.file):
        file_type = Path(args.file).suffix
        if file_type == '.log':
            return [args.file]
        else:
            raise Exception("Wrong format file")
    else:
        raise Exception("No such file or directory")


line_format = re.compile(
    r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|.*) - - '
    r'\[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} '
    r'(\+|\-)\d{4})\] ((\"(POST|GET|PUT|DELETE|HEAD) )(?P<url>.+)(HTTP\/1\.1")) '
    r'(?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["])')

for file in path_type():
    with open(file, 'r') as logfile:

        dict_requests = defaultdict(int)
        dict_methods = defaultdict(lambda: {"GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "HEAD": 0})
        dict_count_ip = {"count_ip": defaultdict(int)}
        dict_client_error = defaultdict(lambda: defaultdict(int))
        dict_server_error = defaultdict(lambda: defaultdict(int))

        for line in logfile.readlines():
            data = re.search(line_format, line)

            if data:
                datadict = data.groupdict()
                ip = datadict["ipaddress"]
                datetimestring = datadict["dateandtime"]
                url = datadict["url"]
                status = datadict["statuscode"]
                bytessent = datadict["bytessent"]
                referrer = datadict["refferer"]
                useragent = datadict["useragent"]
                method = data.group(6)

                dict_requests["count_requests"] += 1
                dict_requests = dict(dict_requests)
                dict_methods["count_method"][method] += 1
                dict_methods = dict(dict_methods)
                dict_count_ip["count_ip"][ip] += 1


                def error_request(dict_error: dict):
                    dict_error[url]['method'] = method
                    dict_error[url]['url'] = url
                    dict_error[url]['status'] = status
                    dict_error[url]['ip'] = ip
                    dict_error[url]['count'] += 1
                    dict_error[url] = dict(dict_error[url])


                if 400 <= int(status) < 500:
                    error_request(dict_client_error)

                if 500 <= int(status) < 600:
                    error_request(dict_server_error)

        top_ip = Counter(dict_count_ip["count_ip"])
        top_ip = top_ip.most_common(10)
        dict_count_ip["count_ip"] = list(dict(top_ip).keys())


        def top_ten_request(dict_request: dict) -> dict:
            # dict_request: {'/opencartadmin ': {'method': 'GET', 'url': '/opencartadmin ', 'status': '404',
            # 'ip': '192.168.50.147', 'count': 6})}
            dict_url = {}
            for i in dict_request:
                dict_url[i] = dict_request[i]["count"]
            count_request = Counter(dict_url)
            count_request = count_request.most_common(10)
            top_request = {}
            for i in count_request:
                key = i[0]
                top_request[key] = dict_request[key]
            return top_request


        top_client_error = top_ten_request(dict_client_error)
        top_server_error = top_ten_request(dict_server_error)

        statistic = {
                    "count_request": dict_requests,
                    "methods": dict_methods,
                    "ip": dict_count_ip,
                    "client_error": top_client_error,
                    "server_error": top_server_error}

    file_name = Path(file).stem
    with open(f'{file_name}_log_results.json', "w") as outfile:
        json.dump(statistic, outfile, indent=4)
