"""System uptime and device timestamps, in integer nanoseconds."""

load("lib/huawei.star", huawei_collect = "collect")
load("lib/juniper.star", juniper_collect = "collect")

def collect(device):
    if device.type == "huawei":
        return huawei_collect(device)
    if device.type == "juniper":
        return juniper_collect(device)
    fail("uptime: unsupported device type: " + device.type)
