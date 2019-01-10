# -*- coding: utf-8 -*-

import calendar
import logging
from collections import defaultdict
from cymruwhois import Client as Whois
from datetime import datetime
from functools import wraps
from ipaddress import IPv4Address, IPv4Network, AddressValueError

class ReqData:
    def __init__(self, data):
        self._paths = set()
        self._hosts = set()
        self._user_agents = set()
        self._req_sizes = set()
        self._timestamps = []
        self._geo_country_name = data.get('geoip').get('country_name')
        self.update(data)

    @property
    def paths(self): return self._paths

    @property
    def hosts(self): return self._hosts

    @property
    def user_agents(self): return self._user_agents

    @property
    def geo_country_name(self): return self._geo_country_name

    @property
    def req_sizes(self): return self._req_sizes

    @property
    def timestamps(self): return self._timestamps

    def update(self, data):
        path = data.get('path')
        host = data.get('http_host')
        user_agent = data.get('user_agent_raw')
        if path: self._paths.add(path)
        if host: self._hosts.add(host)
        if user_agent: self._user_agents.add(user_agent)
        self._timestamps.append(calendar.timegm(datetime.strptime(data['@timestamp'],
                                                                  "%Y-%m-%dT%H:%M:%S.%fZ").timetuple()))
        self._timestamps.sort()


def score(points):
    def wrapper(f):
        @wraps(f)
        def wrapped(self):
            return f(self), points
        return wrapped
    return wrapper


class Checklist:
    def __init__(self, interval, min_score):
        self.interval = interval
        self.min_score = min_score
        self.data = {}
        self.ip_sameorigin_count = {}
        self.cur_addr = None
        self.cur_req = None

    def _fill_ip_sameorigin_count(self, min_len):
        ip2net = {}
        net2ip_count = defaultdict(int)
        addrs = list(self.data.keys())
        for each in Whois().lookupmany(addrs):
            try:
                net = IPv4Network(each.prefix)
            except AddressValueError:
                continue
            if net.prefixlen < min_len: continue
            for idx, addr in enumerate(addrs):
                if IPv4Address(addr) in net:
                    net2ip_count[net] += 1
                    ip2net[addr] = net
                    del addrs[idx]
        for ip, net in ip2net.items():
            self.ip_sameorigin_count[ip] = net2ip_count[net] - 1

    def add_data(self, addr, source):
        req_data = self.data.get(addr)
        if req_data:
            req_data.update(source)
        else:
            self.data[addr] = ReqData(source)

    def check(self):
        results = []
        for self.cur_addr in self.data.keys():
            self.cur_req = self.data[self.cur_addr]
            score = 0
            matched = []
            for check, id, comment in ((f, n[3:].upper(), f.__doc__) for n, f in vars(self.__class__).items()
                                       if callable(f) and n.startswith('if_')):
                match, points = check(self)
                if match:
                    score += points
                    matched.append({'check': id, 'score': points, 'description': comment})
            if score >= self.min_score: results.append({'address': self.cur_addr, 'total_score': score,
                                                        'min_score': self.min_score, 'details': matched})
            logging.debug('{} checked'.format(self.cur_addr), extra={'score': score, 'details': matched,
                                                                     'data': self.cur_req})
        return results
