"""Juniper system uptime collector."""

load("lib/uptime.star", "match", "result", "timestamp")

def collect(device):
    output = device.execute("show system uptime")
    current = match(r"(?m)^Current time:\s*([^\r\n]+)", output, "current time")[1]
    booted = match(r"(?m)^System booted:\s*([^\r\n(]+)\s*\(", output, "system boot time")[1]
    clock = timestamp(current)
    boot = timestamp(booted)
    return result(clock - boot, boot, clock)
