"""Shared timestamp handling; all platform policy lives in Starlark."""

load("re.star", "re")
load("time.star", "time")

def match(pattern, text, field):
    value = re.search(pattern, text)
    if value == None:
        fail("uptime: missing or invalid " + field)
    return value

def timestamp(text, default_zone = None):
    # Whitespace varies in Huawei StartupTime; normalize before parsing.
    text = " ".join(text.strip().split()).replace("/", "-")
    parts = match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(.*)$", text, "timestamp")
    value, zone = parts[1], parts[2].strip()
    if not zone:
        zone = default_zone
    if not zone:
        fail("uptime: timestamp has no timezone")
    offset = re.search(r"^(?:UTC)?([+-]\d{2}:\d{2})(?: [A-Za-z]+)?$", zone)
    if offset != None:
        return time.parse_ns(value + offset[1], "2006-01-02 15:04:05-07:00")
    if zone in ["UTC", "GMT", "Z"]:
        return time.parse_ns(value, "2006-01-02 15:04:05", "UTC")
    if zone == "MSK":
        return time.parse_ns(value, "2006-01-02 15:04:05", "Europe/Moscow")
    fail("uptime: unknown timezone: " + zone)

def result(uptime, boot, clock):
    if uptime < 0 or boot < 0 or clock < 0 or boot > clock:
        fail("uptime: negative duration or invalid timestamps")
    return {"up-time": uptime, "boot-time": boot, "current-datetime": clock}
