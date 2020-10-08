# Copyright 2019 Splunk, Inc.
#
# Use of this source code is governed by a BSD-2-clause-style
# license that can be found in the LICENSE-BSD2 file or at
# https://opensource.org/licenses/BSD-2-Clause
import random
import pytest
from jinja2 import Environment

from .sendmessage import *
from .splunkutils import *
from .timeutils import *

env = Environment()

#
# Oct 8 15:00:25 DEVICENAME time=1570561225|hostname=devicename|severity=Informational|confidence_level=Unknown|product=IPS|action=Drop|ifdir=inbound|ifname=bond2|loguid={0x5d9cdcc9,0x8d159f,0x5f19f392,0x1897a828}|origin=1.1.1.1|time=1570561225|version=1|attack=Streaming Engine: TCP Segment Limit Enforcement|attack_info=TCP segment out of maximum allowed sequence. Packet dropped.|chassis_bladed_system=[ 1_3 ]|dst=10.10.10.10|origin_sic_name=CN=something_03_local,O=devicename.domain.com.p7fdbt|performance_impact=0|protection_id=tcp_segment_limit|protection_name=TCP Segment Limit Enforcement|protection_type=settings_tcp|proto=6|rule=393|rule_name=10.384_..|rule_uid={9F77F944-8DD5-4ADF-803A-785D03B3A2E8}|s_port=46455|service=443|smartdefense_profile=Recommended_Protection_ded9e8d8ee89d|src=1.1.1.2|
def test_checkpoint_splunk_ips(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm time={{ epoch }}|hostname={{ host }}-lm|severity=Informational|confidence_level=Unknown|product=IPS|action=Drop|ifdir=inbound|ifname=bond2|loguid={{ host }}{0x5d9cdcc9,0x8d159f,0x5f19f392,0x1897a828}|origin=1.1.1.1|time={{ epoch }}|version=1|attack=Streaming Engine: TCP Segment Limit Enforcement|attack_info=TCP segment out of maximum allowed sequence. Packet dropped.|chassis_bladed_system=[ 1_3 ]|dst=10.10.10.10|origin_sic_name=CN={{ host }},O=devicename.domain.com.p7fdbt|performance_impact=0|protection_id=tcp_segment_limit|protection_name=TCP Segment Limit Enforcement|protection_type=settings_tcp|proto=6|rule=393|rule_name=10.384_..|rule_uid={9F77F944-8DD5-4ADF-803A-785D03B3A2E8}|s_port=46455|service=443|smartdefense_profile=Recommended_Protection_ded9e8d8ee89d|src=1.1.1.2|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netids host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# $Oct 8 15:48:31 DEVICENAME time=1570564111|hostname=devicename|product=Firewall|action=Drop|ifdir=inbound|ifname=bond1|loguid={0x5d9ce80f,0x8d0555,0x5f19f392,0x18982828}|origin=1.1.1.1|time=1570564111|version=1|chassis_bladed_system=[ 1_1 ]|dst=10.10.10.10|inzone=External|origin_sic_name=CN=something_03_local,O=devicename.domain.com.p7fdbt|outzone=Internal|proto=6|rule=402|rule_name=11_..|rule_uid={C8CD796E-7BD5-47B6-90CA-B250D062D5E5}|s_port=33687|service=23|src=1.1.1.2|
def test_checkpoint_splunk_firewall(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm time={{ epoch }}|hostname={{ host }}-lm|product=Firewall|action=Drop|ifdir=inbound|ifname=bond1|loguid={{ host }}{0x5d9ce80f,0x8d0555,0x5f19f392,0x18982828}|origin=1.1.1.1|time={{ epoch }}|version=1|chassis_bladed_system=[ 1_1 ]|dst=10.10.10.10|inzone=External|origin_sic_name=CN={{ host }},O=devicename.domain.com.p7fdbt|outzone=Internal|proto=6|rule=402|rule_name=11:..|rule_uid={C8CD796E-7BD5-47B6-90CA-B250D062D5E5}|s_port=33687|service=23|src=1.1.1.2|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netfw host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# def test_checkpoint_splunk_firewall_noise(
#     record_property, setup_wordlist, setup_splunk, setup_sc4s
# ):
#     host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

#     dt = datetime.datetime.now()
#     iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

#     # Tune time functions for Checkpoint
#     epoch = epoch[:-7]

#     mt = env.from_string(
#         "{{ mark }} {{ bsd }} {{ host }}-lm time={{ epoch }}|hostname={{ host }}-lm|product=Firewall|action=Drop|ifdir=inbound|ifname=bond1|loguid={0x5d9ce80f,0x8d0555,0x5f19f392,0x18982828}|origin=1.1.1.1|time={{ epoch }}|version=1|chassis_bladed_system=[ 1_1 ]|dst=10.10.10.10|inzone=External|origin_sic_name=CN={{ host }},O=devicename.domain.com.p7fdbt|outzone=Internal|proto=6|rule=402|rule_name=11:..|rule_uid={C8CD796E-7BD5-47B6-90CA-B250D062D5E5}|s_port=33687|service=23|src=1.1.1.2|\n"
#     )
#     message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

#     sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])
#     sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])
#     sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])
#     sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

#     st = env.from_string(
#         'search _time={{ epoch }} index=netfw host="{{ host }}" sourcetype="cp_log"'
#     )
#     search = st.render(
#         epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
#     )

#     resultCount, eventCount = splunk_single(setup_splunk, search)

#     record_property("host", host)
#     record_property("resultCount", resultCount)
#     record_property("message", message)

#     assert resultCount == 1


def test_checkpoint_splunk_firewall2(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm time={{ epoch }}|hostname={{ host }}-lm|severity=Medium|product=Firewall|action=Drop|ifdir=inbound|ifname=eth1|loguid={{ host }}{0x0,0x0,0x0,0x0}|origin=111.89.111.53|originsicname=CN\={{ host }},O\=cma-xx.xx.net.xx|sequencenum=64|time={{epoch}}|version=5|dst=10.11.11.11|inspection_category=anomaly|foo=bar: bat mark||\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netfw host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


def test_checkpoint_vsplunk_firewall(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm time={{ epoch }}|hostname={{ host }}-lm|severity=Medium|product=Firewall|action=Drop|ifdir=inbound|ifname=eth1|loguid={{ host }}{0x0,0x0,0x0,0x0}|origin=111.89.111.53|originsicname=CN\=blah-v_{{ host }},O\=cma-xx.xx.net.xx|sequencenum=64|time={{epoch}}|version=5|dst=10.11.11.11|inspection_category=anomaly|foo=bar: bat mark||\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netfw host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 12:01:16 DEVICENAME |hostname=DEVICENAME|product=mds-query-tool|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\=cp_mgmt,o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time=1570641309|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login|
def test_checkpoint_splunk_mds(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm |hostname={{ host }}-lm|product=mds-query-tool|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\={{ host }},o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time={{ epoch }}|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 12:01:16 DEVICENAME|hostname=DEVICENAME|product=CPMI Client|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\=cp_mgmt,o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time=1570641173|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login
def test_checkpoint_splunk_cpmi(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm |hostname={{ host }}-lm|product=CPMI Client|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\={{ host }},o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time={{ epoch }}|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 12:01:16 DEVICENAME |hostname=DEVICENAME|product=WEB_API|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\=cp_mgmt,o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time=1570640578|version=5|administrator=tufinapi|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login
def test_checkpoint_splunk_web_api(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }}-lm |hostname={{ host }}-lm|product=WEB_API|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\={{ host }},o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time={{ epoch }}|version=5|administrator=tufinapi|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 11:05:15 DEVICENAME time=1570633513|hostname=DEVICENAME|product=SmartConsole|action=Accept|ifdir=outbound|origin=1.1.1.1|4.4.4.4|sequencenum=1|time=1570633513|version=5|additional_info=Authentication method: Password based application token|administrator=psanadhya|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log In|operation_number=10|subject=Administrator Login|
def test_checkpoint_splunk_smartconsole(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }} time={{ epoch }}|hostname={{ host }}|product=SmartConsole|action=Accept|ifdir=outbound|origin=1.1.1.1|4.4.4.4|sequencenum=1|time={{ epoch }}|version=5|additional_info=Authentication method: Password based application token|administrator=psanadhya|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log In|operation_number=10|subject=Administrator Login|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# <6>kernel: sd 2:0:0:0: SCSI error: return code = 0x00040000
def test_checkpoint_splunk_os(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))
    pid = random.randint(1000, 32000)

    mt = env.from_string(
        "{{ mark }}kernel: sd 2:0:0:0: SCSI error: return code = 0x{{pid}}\n"
    )
    message = mt.render(mark="<6>", pid=pid)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search earliest=-1m@m latest=+1m@m index=osnix "0x{{ pid }}" sourcetype="nix:syslog"'
    )
    search = st.render(host=host, pid=pid)

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# time=1586182935|hostname=xxxx-xxxx|product=Syslog|ifdir=inbound|loguid={0x0,0x0,0x0,0x0}|origin=10.0.0.164|sequencenum=3|time=1586182935|version=5|default_device_message=<134>ctasd[5665]: Save SenderId lists finished |facility=local use 0|
def test_checkpoint_splunk_os_nested(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "{{ mark }} {{ bsd }} {{ host }} time={{ epoch }}|hostname={{ host }}|product=Syslog|ifdir=inbound|loguid={{ host }}{0x0,0x0,0x0,0x0}|origin=10.0.0.0|sequencenum=3|time={{ epoch }}|version=5|default_device_message=<134>ctasd[5665]: Save SenderId lists finished |facility=local use 0|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="nix:syslog"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

checkpoint_rfc5424 = [r'{{ mark }}1 {{ iso }}Z {{ host }} CheckPoint 30513 - [action:"Accept"; flags:"18692"; ifdir:"inbound"; ifname:"bond1"; loguid:"{0x5e6b01de,0x42,0x8b1ba995,0xc0000000}"; origin:"a.b.c.d"; time:"1584071134"; version:"1"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={2B1357A0-148C-9D41-8E13-43150189C688};mgmt=fwmgt.xxx.edu;date=1582909094;policy_name=fwcons-fwcl1_Simplified]"; dst:"e.f.g.h"; inzone:"Internal"; origin_sic_name:"myouinfohere"; outzone:"External"; product:"VPN-1 & FireWall-1"; proto:"17"; rule:"1"; rule_uid:"{2548FE8F-60C9-4914-8C28-8B0BC9378B3F}"; s_port:"60131"; service:"53"; service_id:"domain-udp"; src:"a.b.c.d";]']
@pytest.mark.parametrize("event", checkpoint_rfc5424)
def test_checkpoint_5424(
    record_property, setup_wordlist, setup_splunk, setup_sc4s, event
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]
    iso = dt.isoformat()[0:19]

    mt = env.from_string(event + "\n")
    message = mt.render(mark="<134>", iso=iso, host=host)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="nix:syslog"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1