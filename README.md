# log-analyzer
> Script parses the latest log file and generates a report

### Usage
Run `log_analyzer.py` to generate report with default parameters

```bash
usage: log_analyzer.py [-h] [-c CONFIG]
optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configuration file in YAML format
```

### Configuration
Available configuration options:
    `"REPORT_SIZE": 1000` - amount of links to output into report
    `"REPORT_DIR": "./reports"` - folder for storing generated reports
    `"LOG_DIR": "./log"` - folder with log files to parse
    `"LOG_FILE": None` - filename for storing script log
    `"CONFIG_FILE": "config.yaml"` - filename of a custom configuration file
    `"LOGGING_LEVEL": "info"` - logging level; must be one of ["info", "error", "exception"] 
    `"PARSING_ERROR_LIMIT": 50` - parsing error budget in %
    `"TEMPLATE_FILENAME": "report.html"` - filename of a report template