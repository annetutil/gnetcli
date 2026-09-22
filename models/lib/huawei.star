"""Huawei VRP uptime collector."""

load("re.star", "re")
load("lib/uptime.star", "match", "result", "timestamp")

def collect(device):
    version = device.execute("display version")
    clock_output = device.execute("display clock")
    # The first match is system uptime; subsequent matches describe boards.
    uptime_line = match(r"(?m)^([^\r\n]*uptime is[^\r\n]*)", version, "system uptime")[1]
    uptime_match = match(
        r"(?m)^.*uptime is\s+(?:(\d+) weeks?,?\s*)?(?:(\d+) days?,?\s*)?(?:(\d+) hours?,?\s*)?(?:(\d+) minutes?\s*)?\r?$",
        uptime_line,
        "system uptime",
    )
    units = [7 * 86400, 86400, 3600, 60]
    seconds = 0
    found = False
    for i in range(4):
        if uptime_match[i + 1]:
            seconds += int(uptime_match[i + 1]) * units[i]
            found = True
    if not found:
        fail("uptime: empty duration")
    uptime = seconds * 1000000000

    lines = clock_output.strip().splitlines()
    if not lines:
        fail("uptime: empty clock")
    clock_line = lines[0].strip()
    clock_parts = match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(.*)$", clock_line, "clock")
    zone = clock_parts[1].strip()
    if not zone:
        zone = match(r"(?m)^Time Zone.* : (\S+)\s*$", clock_output, "clock timezone")[1]
    clock = timestamp(clock_line, zone)
    startup = re.search(r"(?m)^\s*StartupTime\s+([^\r\n]+)", version)
    boot = timestamp(startup[1], zone) if startup != None else clock - uptime
    return result(uptime, boot, clock)
