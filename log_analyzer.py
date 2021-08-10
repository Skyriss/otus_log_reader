#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import argparse
import os
import re
import gzip
import logging
import statistics
import sys
from collections import defaultdict, namedtuple
from string import Template
import yaml

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "LOG_FILE": None,
    "CONFIG_FILE": "config.yaml",
    "LOGGING_LEVEL": "info",
    "PARSING_ERROR_LIMIT": 50,
    "TEMPLATE_FILENAME": "report.html",
}
logfile_name_template = re.compile(r"^nginx-access-ui\.log-(?P<date>\d{8})(?P<extension>|\.gz)$")
Logfile = namedtuple("Logfile", "filename date")


def read_file(filename):
    """Reads whole text file"""
    with open(filename, "rt", encoding="utf-8") as open_file:
        return open_file.read()


def write_file_content(filename, content):
    """Writes content to a file"""
    directory = os.path.dirname(filename)
    if not os.path.exists(directory):
        os.makedirs(directory)

    with open(filename, "w", encoding="utf-8") as open_file:
        open_file.write(content)


def read_file_lines(filename):
    """Reads logfile by lines"""
    try:
        file_open = gzip.open if filename.endswith(".gz") else open
        with file_open(filename, "rt", encoding="utf-8") as open_file:
            for line in open_file:
                yield line.strip()
    except IOError as err:
        logging.exception("During reading '%s' file error occurred: %s", filename, err)
        raise


def get_last_logfile(log_dir):
    if not os.path.exists(log_dir):
        return None
    last_logfile = Logfile("", "")
    last_log_date = ""
    for file in os.listdir(log_dir):
        matched = logfile_name_template.match(file)
        if matched:
            try:
                file_date = datetime.datetime.strptime(matched.groupdict()["date"], "%Y%m%d")
            except ValueError:
                logging.debug(
                    "Cannot convert '%s' to datetime. Skipping '%s' file",
                    matched.groupdict()["date"],
                    file
                )
                continue
            if not last_log_date or file_date >= last_log_date:
                last_log_date = file_date
                last_logfile = Logfile(os.path.join(log_dir, file), file_date)
    return last_logfile


def generate_report_data(request_time_dict, total_request_count, total_request_time, report_size):
    """Collects all data needed for report and put it into dict"""

    def _time_sort_func(time_list):
        """Returns summarized request_time"""
        return sum(time_list[1])

    request_stats = []
    for request, time in sorted(request_time_dict.items(), key=_time_sort_func, reverse=True):
        request_stats.append({
            "url": request,
            "count": len(time),
            "time_sum": sum(time),
            "time_avg": sum(time)/len(time),
            "time_max": max(time),
            "time_med": statistics.median(time),
            "time_perc": sum(time)/total_request_time,
            "count_perc": len(time)/total_request_count})
        if len(request_stats) == report_size:
            break
    return request_stats


def generate_report(template_file, report_data):
    """Generates report from a template"""
    try:
        report_template = Template(read_file(template_file))
    except IOError as err:
        logging.exception("Can't read template file %s: %s", template_file, err)
        raise
    return report_template.safe_substitute(table_json=str(report_data))


def parse_log_string(logline):
    """Parses string of a log"""
    splitted_string = logline.split(" ")
    if not splitted_string[7].startswith("/") and not splitted_string[7].startswith("http"):
        raise ValueError("URL not found")
    return splitted_string[7], float(splitted_string[-1])


def parse_logfile(log_filename, error_limit):
    """Parses log file and calculates total values"""
    request_time_dict = defaultdict(list)
    total_request_count = 0
    total_request_time = 0
    err_count = 0
    for line in read_file_lines(log_filename):
        try:
            url, load_time = parse_log_string(line)
        except (IndexError, ValueError) as err:
            logging.error("Got error while parsing '%s': %s", line, err)
            err_count += 1
            continue
        if url not in request_time_dict:
            request_time_dict[url] = []
        request_time_dict[url].append(load_time)
        total_request_count += 1
        total_request_time += load_time

    error_rate = 100 * err_count / total_request_count
    if error_rate > error_limit:
        raise RuntimeError("Parsing error limit exceeded! Failed to parse more than {}% ({}/{}) requests".format(
            error_rate,
            err_count,
            total_request_count
        ))
    logging.debug("Found %s parsing errors in %s lines", err_count, total_request_count)
    return request_time_dict, total_request_count, total_request_time


def parse_args():
    """Parses arguments and put it into args variable"""
    parser = argparse.ArgumentParser(description="LogParser")
    parser.add_argument("-c", "--config", action="store", default="config.yml", help="Configuration file in YAML")
    return vars(parser.parse_args())


def gen_config(config_file):
    """Updates values in config variable with values from config file"""
    local_config = config
    try:
        file_content = read_file(config_file)
        if file_content:
            new_config = yaml.safe_load(file_content)
            for key, value in new_config.items():
                local_config.update({key: value})
    except (IOError, TypeError) as err:
        logging.exception("Error while reading config file: %s", err)
        raise
    return local_config


def set_logging(log_level, log_file=None):
    """Configures logging format"""
    logging.basicConfig(
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
        level=log_level.upper(),
        filename=log_file,
    )


def main():
    valid_logging_levels = ["info", "error", "exception"]
    args = parse_args()
    configuration = gen_config(args["config"])
    if configuration["LOGGING_LEVEL"] not in valid_logging_levels:
        raise ValueError("'{}' is not valid logging level. Choose one of {}".format(
            configuration["LOGGING_LEVEL"],
            valid_logging_levels)
        )
    set_logging(configuration["LOGGING_LEVEL"], configuration["LOG_FILE"])

    last_logfile = get_last_logfile(configuration["LOG_DIR"])
    if not last_logfile.filename:
        logging.info("No logfiles found in %s", configuration["LOG_DIR"])
        sys.exit()
    logging.info("The latest logfile: %s", last_logfile.filename)

    report_file = os.path.join(
        configuration["REPORT_DIR"],
        "report-{}.html".format(last_logfile.date.strftime("%Y.%m.%d"))
    )
    if os.path.exists(report_file):
        logging.info("Nothing to do. Report '%s' already exists", report_file)
        sys.exit()

    try:
        request_time_dict, total_request_count, total_request_time = parse_logfile(
            str(last_logfile.filename),
            configuration["PARSING_ERROR_LIMIT"]
        )
    except RuntimeError as err:
        logging.exception("During parsing request data an error occurred: %s", err)
        sys.exit(1)
    except IOError:
        sys.exit(1)

    report_data = generate_report_data(
        request_time_dict,
        total_request_count,
        total_request_time,
        configuration["REPORT_SIZE"]
    )

    try:
        generated_report = generate_report(configuration["TEMPLATE_FILENAME"], report_data)
    except IOError:
        sys.exit(1)

    write_file_content(report_file, generated_report)
    logging.info("Done! Report saved to %s", report_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Ctrl+C was pressed! Bye!")
    except Exception as ex:
        logging.exception("During execution an unexpected exception occurred: %s", ex)
