"""
Shared constants and defaults for DetectBot Portal.
"""

ENVIRONMENTS = ["prod", "dev", "test", "uat", "dr", "unknown"]
ZONES = ["dmz", "internal", "cloud", "partner", "unknown"]
OS_TYPES = ["linux", "windows", "darwin", "unix", "container", "unknown"]
WEB_SERVER_TYPES = ["nginx", "apache", "iis", "tomcat", "unknown"]
CRITICALITIES = ["critical", "high", "medium", "low"]
POLICY_MODES = ["safe", "balanced", "deep", "custom"]
INPUT_TYPES = [
    "nginx_dump",
    "apache_dump",
    "watch_dir",
    "manual_json",
    "kafka_event",
    "unknown",
]
SEVERITIES = ["critical", "high", "medium", "low", "unknown"]

DEFAULT_ALLOW_MIME = [
    "text/html",
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/json",
    "application/xml",
    "image/",
]

DEFAULT_ALLOW_EXT = [
    ".html",
    ".htm",
    ".css",
    ".js",
    ".json",
    ".xml",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
]

DEFAULT_EXCLUDE_PATHS = [
    "/var/log",
    "/tmp",
]
