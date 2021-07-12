#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import argparse
import os
import re
import gzip
import logging
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


class File:
    """Implements methods for working with text files"""

    @staticmethod
    def read_file(filename):
        """Reads whole text file"""
        with open(filename, "rt", encoding="utf-8") as open_file:
            return open_file.read()

    @staticmethod
    def write_file_content(directory, filename, content):
        """Writes content to a file"""
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(os.path.join(directory, filename), "w", encoding="utf-8") as open_file:
            open_file.write(content)

    @staticmethod
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


class Log:
    """Implements methods for logs reading"""
    def __init__(self, log_dir):
        self.log_dir = log_dir

    logfile_name_template = re.compile(r"^nginx-access-ui\.log-(?P<date>\d{8})(?P<extension>|\.gz)$")
    Logfile = namedtuple("Logfile", "filename date")

    def _list_log_files(self, log_dir):
        """Lists log files in directory"""
        for file in os.listdir(log_dir):
            matched = self.logfile_name_template.match(file)
            if matched:
                yield {
                    "filename": file,
                    "date": datetime.datetime.strptime(matched.groupdict()["date"], "%Y%m%d"),
                }

    def get_last_logfile(self):
        """Finds out logifile with a highest datestamp in the name"""
        if not os.path.exists(self.log_dir):
            return None
        last_logfile = self.Logfile("", "")
        last_log_date = ""
        for file in self._list_log_files(self.log_dir):
            if not last_log_date:
                last_log_date = file["date"]
            if file["date"] > last_log_date:
                last_logfile = self.Logfile(os.path.join(self.log_dir, file["filename"]), file["date"])
                last_log_date = file["date"]
        return last_logfile


class Report:
    """Implements methods for report generating"""
    def __init__(self, report_dir, report_size, template_file):
        self.template_file = template_file
        self.directory = report_dir
        self.size = report_size
        self.name = ""
        self.data = []

    @staticmethod
    def get_report_name(log_date):
        """Generates report name"""
        return "report-{}.html".format(log_date.strftime("%Y.%m.%d"))

    def generate_report(self):
        """Generates report from a template"""
        try:
            report_template = Template(File.read_file(self.template_file))
        except IOError as err:
            logging.exception("Can't read template file %s: %s", self.template_file, err)
            raise
        return report_template.safe_substitute(table_json=str(self.data))

    @staticmethod
    def _time_sort_func(time):
        """Returns summarized request_time"""
        return sum(time[1])

    def generate_report_data(self, request_time_dict, total_request_count, total_request_time):
        """Collects all data needed for report and put it into dict"""
        request_stats = []
        for request, time in sorted(request_time_dict.items(), key=self._time_sort_func, reverse=True):
            request_stats.append({
                "url": request,
                "count": len(time),
                "time_sum": sum(time),
                "time_avg": sum(time)/len(time),
                "time_max": max(time),
                "time_med": median(time),
                "time_perc": sum(time)/total_request_time,
                "count_perc": len(time)/total_request_count})
            if len(request_stats) == self.size:
                break
        return request_stats


class LogParser:
    """Implements method for parsing log files"""
    def __init__(self, error_limit):
        self.error_limit = error_limit

    @staticmethod
    def _parse_log_string(logline):
        """Parses string of a log"""
        splitted_string = logline.split(" ")
        if not splitted_string[7].startswith("/") and not splitted_string[7].startswith("http"):
            raise ValueError("URL not found")
        return splitted_string[7], float(splitted_string[-1])

    def parse_logfile(self, log_filename):
        """Parses log file and calculates total values"""
        request_time_dict = defaultdict(list)
        total_request_count = 0
        total_request_time = 0
        err_count = 0
        for line in File.read_file_lines(log_filename):
            try:
                url, load_time = self._parse_log_string(line)
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
        if error_rate > self.error_limit:
            raise ValueError("Parsing error budget exceeded! Failed to parse more than {}% ({}/{}) requests".format(
                error_rate,
                err_count,
                total_request_count
            ))
        logging.debug("Found %s parsing errors in %s lines", err_count, total_request_count)
        return request_time_dict, total_request_count, total_request_time


def median(lst):
    """Calculates median of a list"""
    sorted_lst = sorted(lst)
    lst_len = len(lst)
    index = (lst_len - 1) // 2
    if lst_len % 2:
        return sorted_lst[index]
    return (sorted_lst[index] + sorted_lst[index + 1])/2.0


def parse_args():
    """Parses arguments and put it into args variable"""
    parser = argparse.ArgumentParser(description="LogParser")
    parser.add_argument("-c", "--config", action="store", default="config.yml", help="Configuration file in YAML")
    return vars(parser.parse_args())


def parse_config_file(config_file):
    """Reads config file and update script config"""
    file_content = File.read_file(config_file)
    if file_content:
        new_config = yaml.load(file_content, Loader=yaml.SafeLoader)
        for key, value in new_config.items():
            yield {key: value}


def update_config(config_file):
    """Updates values in config variable with values from file"""
    try:
        for item in parse_config_file(config_file):
            config.update(item)
    except (IOError, TypeError) as err:
        logging.exception("Error while reading config file: %s", err)
        sys.exit(1)


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
    if "config" in args:
        update_config(args["config"])
    if config["LOGGING_LEVEL"] not in valid_logging_levels:
        raise ValueError("'{}' is not valid logging level. Choose one of {}".format(
            config["LOGGING_LEVEL"],
            valid_logging_levels)
        )
    set_logging(config["LOGGING_LEVEL"], config["LOG_FILE"])

    logfile = Log(config["LOG_DIR"])
    last_logfile = logfile.get_last_logfile()
    if not last_logfile.filename:
        logging.info("No logfiles found in %s", config["LOG_DIR"])
        sys.exit()
    logging.info("The latest logfile: %s", last_logfile.filename)

    parser = LogParser(config["PARSING_ERROR_LIMIT"])

    report = Report(
        config["REPORT_DIR"],
        config["REPORT_SIZE"],
        config["TEMPLATE_FILENAME"]
    )
    report.name = report.get_report_name(last_logfile.date)
    if os.path.exists(report.directory) and report.name in os.listdir(report.directory):
        logging.info("Nothing to do. Report %s already exists", os.path.join(report.directory, report.name))
        sys.exit()
    try:
        request_time_dict, total_request_count, total_request_time = parser.parse_logfile(str(last_logfile.filename))
    except KeyError as err:
        logging.exception("During parsing request data an error occurred: %s", err)
        sys.exit(1)
    except IOError:
        sys.exit(1)

    report.data = report.generate_report_data(
        request_time_dict,
        total_request_count,
        total_request_time
    )

    try:
        generated_report = report.generate_report()
    except IOError:
        sys.exit(1)

    File.write_file_content(report.directory, report.name, generated_report)
    logging.info("Done! Report saved to %s", os.path.join(config["REPORT_DIR"], report.name))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Ctrl+C was pressed! Bye!")
    except Exception as ex:
        logging.exception("During execution an unexpected exception occurred: %s", ex)
