#!/usr/bin/env python3
import datetime
from collections import namedtuple
from unittest import mock, TestCase
from log_analyzer import (
    read_file_lines,
    get_last_logfile,
    get_report_name,
    generate_report,
    generate_report_data,
    parse_log_string,
    parse_logfile,
)


def mock_empty_parse_args():
    return vars()


class TestLogAnalyzer(TestCase):
    report_data = [
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
    valid_last_log = Logfile("nginx-access-ui.log-20210630.gz", datetime.datetime(2021, 6, 30, 0, 0))
    log_sample = """1.170.209.160 -  - [29/Jun/2017:03:50:33 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 404 162 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.001
1.165.177.32 -  - [29/Jun/2017:03:50:33 +0300] "GET /export/appinstall_raw/2017-06-29/ HTTP/1.0" 200 28358 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.003
1.165.177.32 -  - [29/Jun/2017:03:50:33 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 404 162 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.001"""
    valid_request_time_dict = {
        "/export/appinstall_raw/2017-06-30/": [0.001, 0.001],
        "/export/appinstall_raw/2017-06-29/": [0.003]
    }
    valid_total_request_count = 3
    valid_total_request_time = 0.005
    valid_report_size = 2
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

    def test_get_last_logfile(self):
        with mock.patch("os.listdir") as mocked_listdir:
            mocked_listdir.return_value = self.listdir
            with mock.patch("os.path.exists") as mocked_path_exists:
                mocked_path_exists.return_value = True
                last_logfile = get_last_logfile("")
                self.assertEqual(self.valid_last_log, last_logfile)

    def test_get_logfile_lines(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="data")):
            for line in read_file_lines(str(self.valid_last_log)):
                self.assertEqual(line, "data")

    def test_parse_log_string(self):
        parsed_log_string = ('/api/v2/banner/782125', 2.45)
        valid_log_string = "1.196.116.32 -  - [29/Jun/2017:03:50:29 +0300] \"GET /api/v2/banner/782125 HTTP/1.1\" 200 1052 \"-\" \"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5\" \"-\" \"1498697426-2190034393-4708-9752865\" \"dc7161be3\" 2.450"
        invalid_log_string = "not_a_log"
        invalid_log_string2 = "1.196.116.32 -  - [29/Jun/2017:03:50:29 +0300] \"GET /api/v2/banner/782125 HTTP/1.1\" 200 1052 \"-\" \"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5\" \"-\" \"1498697426-2190034393-4708-9752865\" \"dc7161be3\""
        invalid_log_string3 = "1.196.116.32 -  - [29/Jun/2017:03:50:29 +0300] \"-\" 200 1052 \"-\" \"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5\" \"-\" \"1498697426-2190034393-4708-9752865\" \"dc7161be3\" 2.450"
        self.assertEqual(parse_log_string(valid_log_string), parsed_log_string)
        with self.assertRaises(IndexError):
            parse_log_string(invalid_log_string)
        with self.assertRaises(ValueError):
            parse_log_string(invalid_log_string2)
        with self.assertRaises(ValueError):
            parse_log_string(invalid_log_string3)

    def test_get_report_name(self):
        self.assertEqual(get_report_name(self.valid_last_log.date), "report-2021.06.30.html")

    def test_generate_report(self):
        valid_report = "This report contains data: [{'url': '/api/', 'count': 2, 'time_sum': 17, 'time_avg': 3, 'time_max': 4, 'time_med': 4, 'time_perc': 0.0, 'count_perc': 0.0}] as list"
        with mock.patch("builtins.open", mock.mock_open(read_data="This report contains data: $table_json as list")) as mock_file:
            """template_file, report_data"""
            self.assertEqual(generate_report(mock_file, self.report_data), valid_report)

    def test_generate_report_data(self):
        generated_report_data = generate_report_data(
            self.valid_request_time_dict,
            self.valid_total_request_count,
            self.valid_total_request_time,
            self.valid_report_size,
        )
        self.assertEqual(generated_report_data, self.valid_report_data)

    def test_parse_logfile(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=self.log_sample)):
            request_time_dict, total_request_count, total_request_time = parse_logfile("some_file", error_limit=50)
            self.assertEqual(request_time_dict, self.valid_request_time_dict)
            self.assertEqual(total_request_count, self.valid_total_request_count)
            self.assertEqual(total_request_time, self.valid_total_request_time)
