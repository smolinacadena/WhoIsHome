#! /usr/bin/env python

import nmap
import time
import socket
import json
import sys
import os
import requests
import itertools
import configparser
from collections import OrderedDict
from configparser import RawConfigParser

def scan():

    hosts = str(get_lan_ip()) + "/24"
    nmap_args = "-sn"

    scanner = nmap.PortScanner()
    scanner.scan(hosts=hosts, arguments=nmap_args)

    hostList = []

    for ip in scanner.all_hosts():
        host = {"ip": ip}
        if "mac" in scanner[ip]["addresses"]:
            host["mac"] = scanner[ip]["addresses"]["mac"].upper()
        hostList.append(host)

    return hostList

def get_lan_ip():

    try:
        return ([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
    except socket.error as e:
        sys.stderr.write(str(e) + "\n")
        sys.exit(e.errno)

def notifySlack(newUsers, leftUsers, existingUsers):

    message = ""
    if len(newUsers) > 0:
        message += ", ".join(newUsers) + " just got home. "

    if len(leftUsers) > 0:
        message = ", ".join(leftUsers) + " just left home. "

    if len(existingUsers) > 0:

        verb = "are" if len(existingUsers) > 1 else "is"
        message += ", ".join(existingUsers) + " " + verb + " still home."

    else:
        message += "No one is home."

    sendSlackWebhook(message)

def sendSlackWebhook(message):

    payload = json.dumps({
        "text": message
    })
    requests.post(slackConfig["webhook_url"], data=payload)

def parseConfigFile():

    scriptDir = os.path.dirname(os.path.realpath(__file__))
    configDir = os.path.join(scriptDir, "config.json")

    jsonFile = open(configDir)
    config = json.load(jsonFile)

    if len(config) < 1:
        sys.stderr.write(
            "Oops, couldn't read the config file. Consult the readme.\n")
        sys.exit(0)

    try:
        slackConfig = config["slack"]
        knownHosts = dict()

        for name, macs in config["hosts"].items():
            knownHosts[name.title()] = [mac.upper() for mac in macs]

    except KeyError as e:
        sys.stderr.write(
            "Please correct your config file. Missing section %s .\n" % str(e))
        sys.exit(0)

    if len(knownHosts) == 0:
        sys.stderr.write(
            "Oops, you did not specify any known hosts. Please correct your config file.\n")
        sys.exit(0)

    if not "webhook_url" in slackConfig or slackConfig["webhook_url"] is None:
        sys.stderr.write(
            "Oops, you did not set up the Webhook integration. Please correct your config file.\n")
        sys.exit(0)

    return slackConfig, knownHosts


# Entry point
if __name__ == "__main__":

    slackConfig, knownHosts = parseConfigFile()
    activeHosts = set()

    while True:

        scannedHosts = [host["mac"] for host in scan() if "mac" in host]
        recognizedHosts = set()

        for name, macs in knownHosts.items():
            for scannedHost in scannedHosts:
                if scannedHost in macs:
                    recognizedHosts.add(name)

        newHosts = recognizedHosts - activeHosts
        leftHosts = activeHosts - recognizedHosts

        if len(newHosts) > 0 or len(leftHosts) > 0:
            notifySlack(newHosts, leftHosts, activeHosts - leftHosts)

        activeHosts = recognizedHosts
        time.sleep(20)