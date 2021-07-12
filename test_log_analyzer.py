#!/usr/bin/env python3
import datetime
from collections import namedtuple
from unittest import mock, TestCase
from log_analyzer import (
    File,
    Log,
    LogParser,
    Report,
    median,
)


def mock_empty_parse_args():
    return vars()

class TestLogAnalyzer(TestCase):
    logfile = Log("")
    log_parser = LogParser(50)
    report = Report(report_dir="", report_size=5, template_file="")
    report.data = [
        {'url': '/api/',
         'count': 2,
         'time_sum': 17,
         'time_avg': 3,
         'time_max': 4,
         'time_med': 4,
         'time_perc': 0.0,
         'count_perc': 0.0},
    ]
    listdir = ["somefile",
               "somefile.gz",
               "nginx-access-ui.log-20170630",
               "nginx-access-ui.log-20170630.gz",
               "nginx-access-ui.log-20170630.bz2",
               "haproxy-access-ui.log-20170630",
               "nginx-error-ui.log-20170630",
               "nginx-access-ui.log-20210630",
               "nginx-access-ui.log-test-20170630"
               "nginx-access-ui.log-20210630",
               "nginx-access-ui.log-20210630.gz",
               ]
    Logfile = namedtuple("Logfile", "filename date")
    valid_last_log = Logfile("nginx-access-ui.log-20210630", datetime.datetime(2021, 6, 30, 0, 0))
    log_sample = """1.170.209.160 -  - [29/Jun/2017:03:50:33 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 404 162 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.001
1.165.177.32 -  - [29/Jun/2017:03:50:33 +0300] "GET /export/appinstall_raw/2017-06-29/ HTTP/1.0" 200 28358 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.003
1.165.177.32 -  - [29/Jun/2017:03:50:33 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 404 162 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.001"""
    valid_request_time_dict = {
        "/export/appinstall_raw/2017-06-30/": [0.001, 0.001],
        "/export/appinstall_raw/2017-06-29/": [0.003]
    }
    valid_total_request_count = 3
    valid_total_request_time = 0.005
    valid_report_data = [
        {
            "url": "/export/appinstall_raw/2017-06-29/",
            "count": 1,
            "time_sum": 0.003,
            "time_avg": 0.003,
            "time_max": 0.003,
            "time_med": 0.003,
            "time_perc": 0.6,
            "count_perc": 0.3333333333333333
         },
        {
            "url": "/export/appinstall_raw/2017-06-30/",
            "count": 2,
            "time_sum": 0.002,
            "time_avg": 0.001,
            "time_max": 0.001,
            "time_med": 0.001,
            "time_perc": 0.4,
            "count_perc": 0.6666666666666666
        }
    ]

    def test_median(self):
        lst = [1, 3, 4, 4, 12]
        mediana = median(lst)
        self.assertEqual(mediana, 4)

    def test_list_log_files(self):
        log_files = [
            {"filename": "nginx-access-ui.log-20170630",
             "date": datetime.datetime(2017, 6, 30, 0, 0),
             },
            {"filename": "nginx-access-ui.log-20170630.gz",
             "date": datetime.datetime(2017, 6, 30, 0, 0),
             },
            {"filename": "nginx-access-ui.log-20210630",
             "date": datetime.datetime(2021, 6, 30, 0, 0),
            },
            {"filename": "nginx-access-ui.log-20210630.gz",
             "date": datetime.datetime(2021, 6, 30, 0, 0),
             }
                     ]
        with mock.patch("os.listdir") as mocked_listdir:
            mocked_listdir.return_value = self.listdir
            counter = 0
            for item in self.logfile._list_log_files("some_dir"):
                counter += 1
                self.assertIn(item, log_files)
            self.assertEqual(len(log_files), counter)

    def test_get_last_logfile(self):
        self.assertEqual(self.logfile.get_last_logfile(), None)
        with mock.patch("os.listdir") as mocked_listdir:
            mocked_listdir.return_value = self.listdir
            with mock.patch("os.path.exists") as mocked_path_exists:
                mocked_path_exists.return_value = True
                self.assertEqual(self.logfile.get_last_logfile(), self.valid_last_log)

    def test_get_logfile_lines(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="data")) as mock_file:
            for line in File.read_file_lines(str(self.valid_last_log)):
                self.assertEqual(line, "data")

    def test_parse_log_string(self):
        parsed_log_string = ('/api/v2/banner/782125', 2.45)
        valid_log_string = "1.196.116.32 -  - [29/Jun/2017:03:50:29 +0300] \"GET /api/v2/banner/782125 HTTP/1.1\" 200 1052 \"-\" \"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5\" \"-\" \"1498697426-2190034393-4708-9752865\" \"dc7161be3\" 2.450"
        invalid_log_string = "not_a_log"
        invalid_log_string2 = "1.196.116.32 -  - [29/Jun/2017:03:50:29 +0300] \"GET /api/v2/banner/782125 HTTP/1.1\" 200 1052 \"-\" \"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5\" \"-\" \"1498697426-2190034393-4708-9752865\" \"dc7161be3\""
        invalid_log_string3 = "1.196.116.32 -  - [29/Jun/2017:03:50:29 +0300] \"-\" 200 1052 \"-\" \"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5\" \"-\" \"1498697426-2190034393-4708-9752865\" \"dc7161be3\" 2.450"
        self.assertEqual(self.log_parser._parse_log_string(valid_log_string), parsed_log_string)
        with self.assertRaises(IndexError):
            self.log_parser._parse_log_string(invalid_log_string)
        with self.assertRaises(ValueError):
            self.log_parser._parse_log_string(invalid_log_string2)
        with self.assertRaises(ValueError):
            self.log_parser._parse_log_string(invalid_log_string3)

    def test_get_report_name(self):
        self.assertEqual(self.report.get_report_name(self.valid_last_log.date), "report-2021.06.30.html")

    def test_generate_report(self):
        valid_report = "This report contains data: [{'url': '/api/', 'count': 2, 'time_sum': 17, 'time_avg': 3, 'time_max': 4, 'time_med': 4, 'time_perc': 0.0, 'count_perc': 0.0}] as list"
        with mock.patch("builtins.open", mock.mock_open(read_data="This report contains data: $table_json as list")) as mock_file:
            self.assertEqual(self.report.generate_report(), valid_report)

    def test_generate_report_data(self):
        generated_report_data = self.report.generate_report_data(
            self.valid_request_time_dict,
            self.valid_total_request_count,
            self.valid_total_request_time
        )
        self.assertEqual(generated_report_data, self.valid_report_data)

    def test_parse_logfile(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=self.log_sample)):
            request_time_dict, total_request_count, total_request_time = self.log_parser.parse_logfile("some_file")
            print(request_time_dict)
            self.assertEqual(request_time_dict, self.valid_request_time_dict)
            self.assertEqual(total_request_count, self.valid_total_request_count)
            self.assertEqual(total_request_time, self.valid_total_request_time)



