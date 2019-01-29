#!/usr/bin/python

import datetime
import re
import argparse
import netaddr
import telepot
from scapy.all import *
from telepot.loop import MessageLoop

from filemanagement import *


def unicode_decode(lst):
    output = set()
    for e in lst:
        try:
            output.add(unicode(e))
        except UnicodeDecodeError:
            continue
    return output


ssids = unicode_decode(load_ssids())
macs = unicode_decode(load_macs())
vendors = unicode_decode(load_vendors())
macs_to_track = unicode_decode(load_macs_to_track())
macs_last_seen = load_macs_last_seen()

interface = None
telegram_uid = None
telegram_token = None

bot = None
loop = None

status_message = ""
packet_counter = 0


def msg_callback(msg):
    global status_message
    global packet_counter

    if not msg:
        return
    if not msg["from"] or not msg["text"]:
        return
    if not msg["from"]["id"] or not telegram_uid:
        return
    if str(msg["from"]["id"]) != str(telegram_uid):
        return
    p = re.compile(ur'(?:[0-9a-fA-F]:?){12}')
    m = re.findall(p, msg["text"])
    text_lower = msg["text"].lower()
    for mac in m:
        mac = mac.lower()
        if "entfolge" in text_lower or "entferne" in text_lower:
            macs_to_track.remove(mac)
        else:
            macs_to_track.add(mac)
        update_macs_to_track(macs_to_track)
    if m and bot:
        bot.sendMessage(telegram_uid, "OK! Folgende MAC-Adressen werden jetzt verfolgt: {}".format(
            ", ".join(macs_to_track)
        ))

    if "status" in text_lower:
        if status_message:
            status_message += "Seit der letzten Abfrage wurden {} Probe Requests empfangen!".format(packet_counter)
        else:
            status_message = "Keine Neuigkeiten. Seit der letzten Abfrage wurden {} Probe Requests empfangen!".format(packet_counter)
        bot.sendMessage(telegram_uid, status_message[:3500])
        status_message = ""
        packet_counter = 0

    if "zeige" in text_lower:
        if "mac" in text_lower:
            bot.sendMessage(telegram_uid, "Insgesamt wurden {} Mac-Adressen erfasst: {}".format(
                len(macs), ", ".join(macs)[:3500]
            ))
        if "ssid" in text_lower:
            bot.sendMessage(telegram_uid, "Insgesamt wurden {} SSIDs erfasst: {}".format(
                len(ssids), ", ".join(ssids)[:3500]
            ))
        if "hersteller" in text_lower or "vendor" in text_lower:
            bot.sendMessage(telegram_uid, "Insgesamt wurden {} Hersteller erfasst: {}".format(
                len(vendors), ", ".join(vendors)[:3500]
            ))


def packet_callback(packet):
    global status_message
    global packet_counter

    if not packet:
        return

    try:
        if packet.type != 0 or packet.subtype != 0x04:
            return
    except AttributeError:
        return

    packet_counter += 1

    log_time = datetime.now()

    mac = packet.addr2

    # parse mac address and look up the organization from the vendor octets
    try:
        parsed_mac = netaddr.EUI(packet.addr2)
        vendor = parsed_mac.oui.registration().org
    except netaddr.core.NotRegisteredError:
        vendor = 'unknown'

    ssid = packet.info

    if ssid and ssid not in ssids:
        ssids.add(ssid)
        update_ssids(ssids)
        status_message += "SSID #{} entdeckt: {}\n".format(len(ssids), ssid)

    if ssid:
        if "dhl" in ssid.lower():
            bot.sendMessage(telegram_uid, "DHL ist vor der Tuer!")
        if "dpd" in ssid.lower():
            bot.sendMessage(telegram_uid, "DPD ist vor der Tuer!")
        if "ups" in ssid.lower():
            bot.sendMessage(telegram_uid, "UPS ist vor der Tuer!")
        if "hermes" in ssid.lower():
            bot.sendMessage(telegram_uid, "Hermes ist vor der Tuer!")
        if "post" in ssid.lower():
            bot.sendMessage(telegram_uid, "Die Post ist vor der Tuer!")

    if mac and mac not in macs:
        mac = mac.lower()
        macs.add(mac)
        update_macs(macs)
        status_message += "MAC #{} entdeckt: {}\n".format(len(macs), mac)

    if vendor and vendor not in vendors:
        vendors.add(vendor)
        update_vendors(vendors)
        status_message += "Hersteller #{} entdeckt: {}\n".format(len(vendors), vendor)

    if mac and mac in macs_to_track:
        try:
            last_seen_date = macs_last_seen[mac]
        except KeyError:
            last_seen_date = log_time
        elapsed_time = last_seen_date - log_time
        minutes = abs(elapsed_time.total_seconds()) / 60
        if minutes > 30:
            bot.sendMessage(telegram_uid, "Das Geraet mit der MAC-Adresse {} (Hersteller: {}) hat sich das erste Mal "
                                          "seit {} Minuten gemeldet. (Es suchte das Netzwerk mit der SSID: {}"
                                          ")".format(mac, vendor, minutes, ssid))
        macs_last_seen[mac] = log_time
        update_macs_last_seen(macs_last_seen)

    print log_time, mac, vendor, ssid


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Probemonitor")
    parser.add_argument('-i', '--interface', help="capture interface")
    parser.add_argument('-u', '--uid', help="Telegram target user id")
    parser.add_argument('-tt', '--telegramtoken', help="Telegram bot token")
    args = parser.parse_args()

    if not args.interface:
        print "error: capture interface not given, try --help"
        sys.exit(-1)

    interface = args.interface
    telegram_uid = args.uid
    telegram_token = args.telegramtoken

    bot = telepot.Bot(telegram_token)
    loop = MessageLoop(bot, msg_callback).run_as_thread()

    sniff(iface=args.interface, prn=packet_callback, store=0)
