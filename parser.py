import argparse
import json
import os
import re
from collections import defaultdict, Counter
from pathlib import Path

parser = argparse.ArgumentParser(description="The process of analyzing the log files")
parser.add_argument(
    "-f", dest="file", action="store", help="Path to logfile or log files"
)
args = parser.parse_args()


def path_type():
    if os.path.isdir(args.file):
        files = filter(lambda x: x.endswith(".log"), os.listdir(args.file))
        log_files = []
        for current_file in list(files):
            current_file = Path().joinpath(args.file).joinpath(current_file)
            log_files.append(current_file)
        return log_files
    elif os.path.isfile(args.file):
        file_type = Path(args.file).suffix
        if file_type == ".log":
            return [args.file]
        else:
            raise Exception("Wrong format file")
    else:
        raise Exception("No such file or directory")


line_format = re.compile(
    r"(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|.*) - - "
    r"\[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} "
    r'(\+|\-)\d{4})\] ((\"(POST|GET|PUT|DELETE|HEAD) )(?P<url>.+)(HTTP\/1\.1")) '
    r'(?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["]) '
    r"(?P<time>\d+$)"
)

for file in path_type():
    with open(file, "r") as logfile:

        dict_requests = defaultdict(int)
        dict_methods = defaultdict(
            lambda: {"GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "HEAD": 0}
        )
        dict_count_ip = {"count_ip": defaultdict(int)}
        dict_client_error = defaultdict(
            lambda: {"method": None, "status": None, "ip": None, "count": 0}
        )
        dict_server_error = defaultdict(
            lambda: {"method": None, "status": None, "ip": None, "count": 0}
        )
        dict_long_requests = defaultdict(
            lambda: {"method": None, "url": None, "ip": None, "time": 0}
        )

        for index, line in enumerate(logfile.readlines()):
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
                requesttime = datadict["time"]

                dict_requests["count_requests"] += 1
                dict_requests = dict(dict_requests)
                dict_methods["count_method"][method] += 1
                dict_methods = dict(dict_methods)
                dict_count_ip["count_ip"][ip] += 1

                dict_long_requests[index]["method"] = method
                dict_long_requests[index]["url"] = url
                dict_long_requests[index]["ip"] = ip
                dict_long_requests[index]["time"] = requesttime

                def error_request(dict_error: dict):
                    dict_error[url]["method"] = method
                    dict_error[url]["status"] = status
                    dict_error[url]["ip"] = ip
                    dict_error[url]["count"] += 1

                if 400 <= int(status) < 500:
                    error_request(dict_client_error)

                if 500 <= int(status) < 600:
                    error_request(dict_server_error)

        top_ip = Counter(dict_count_ip["count_ip"])
        top_ip = top_ip.most_common(10)
        dict_count_ip["count_ip"] = list(dict(top_ip).keys())

        def top_ten_request(dict_request: dict, count: str) -> dict:
            # dict_request: {'/opencartadmin ': {'method': 'GET', 'status': '404',
            # 'ip': '192.168.50.147', 'count': 6})}
            dict_url = {}
            for i in dict_request:
                dict_url[i] = dict_request[i][count]
            count_request = Counter(dict_url)
            count_request = count_request.most_common(10)
            top_request = {}
            for i in count_request:
                key = i[0]
                top_request[key] = dict_request[key]
            return top_request

        top_client_error = top_ten_request(dict_client_error, "count")
        top_server_error = top_ten_request(dict_server_error, "count")
        top_long_requests = top_ten_request(dict_long_requests, "time")

        statistic = {
            "count_request": dict_requests,
            "methods": dict_methods,
            "top_ip": dict_count_ip,
            "top_long_requests": top_long_requests,
            "top_client_error": top_client_error,
            "top_server_error": top_server_error,
        }

    file_name = Path(file).stem
    with open(f"{file_name}_log_results.json", "w") as outfile:
        json.dump(statistic, outfile, indent=4)
