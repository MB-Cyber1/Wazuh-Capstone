"""Replay .ini test cases through wazuh-logtest and check which rule fires.

Runs inside the wazuh-ruletest container with Wazuh's bundled python
(/var/ossec/framework/python/bin/python3) so it can reuse wazuh_logtest.py.

Case format (one section per test, same spirit as Wazuh's ruleset/testing):

    [100201 comsvcs MiniDump of lsass]
    location = EventChannel
    decoder = windows_eventchannel
    rule = 100201
    alert = 14
    log 1 pass = {"win":{...}}
    log 2 fail = {"win":{...}}

  pass  -> must fire rule/alert (and decoder, if given)
  fail  -> must NOT fire that rule
  feed  -> just sent, no check (builds frequency/correlation state)

A line can override the section rule: "log 6 pass 100200:13 = ...".
All lines of a section go through one logtest session, in order.
"""
import configparser
import glob
import os
import re
import sys

sys.path.insert(0, '/var/ossec/framework/scripts')
from wazuh_logtest import WazuhLogtest  # noqa: E402

KEY = re.compile(r'^log (\d+) (pass|fail|feed)(?: (\d+)(?::(\d+))?)?$')


def run_section(name, sec):
    lt = WazuhLogtest(location=sec.get('location', 'stdin'),
                      log_format=sec.get('log_format', 'syslog'))
    lines = []
    for key, value in sec.items():
        m = KEY.match(key)
        if m:
            lines.append((int(m.group(1)), m.group(2), m.group(3), m.group(4), value))
    lines.sort()

    results, token = [], None
    for n, kind, rule, level, event in lines:
        try:
            out = lt.process_log(event, token)
        except ValueError as e:  # ruleset failed to load, bad event, ...
            return [(False, f'log {n} {kind}', f'logtest error: {e}')]
        token = out['token']
        fired = out['output'].get('rule', {})
        got = (str(fired.get('id', '')), str(fired.get('level', '')))
        decoder = (out['output'].get('decoder') or {}).get('name', '')
        if kind == 'feed':
            continue
        want_rule = rule or sec.get('rule')
        want_level = level or sec.get('alert')
        hit = got[0] == want_rule and (not want_level or got[1] == want_level)
        if kind == 'pass':
            ok = hit and (not sec.get('decoder') or decoder == sec.get('decoder'))
        else:
            ok = got[0] != want_rule
        results.append((ok, f'log {n} {kind} {want_rule}', f'got {got[0] or "-"}:{got[1] or "-"} ({decoder or "no decoder"})'))
    if token:
        lt.remove_session(token)
    return results


def main():
    case_dir = sys.argv[1]
    only = sys.argv[2] if len(sys.argv) > 2 else ''
    failed = total = 0
    for path in sorted(glob.glob(os.path.join(case_dir, '*.ini'))):
        if only and only not in os.path.basename(path):
            continue
        cp = configparser.RawConfigParser(delimiters=('=',))
        cp.optionxform = str.lower
        cp.read(path, encoding='utf-8')
        print(f'\n== {os.path.basename(path)}')
        for name in cp.sections():
            for ok, what, detail in run_section(name, cp[name]):
                total += 1
                failed += not ok
                print(f'  [{"PASS" if ok else "FAIL"}] {name} :: {what} -> {detail}')
    print(f'\n{total - failed}/{total} checks passed')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
