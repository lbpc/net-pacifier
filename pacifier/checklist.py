import socket
import statistics

from ipaddress import IPv4Address, IPv4Network
from urllib import parse
from pacifier.pacifier import Checklist, score


class CMSBrute(Checklist):
    @property
    def _is_yandex_bot(self):
        rev = ''
        try:
            rev = socket.gethostbyaddr(self.cur_addr)[0]
        except socket.herror:
            pass
        return '.'.join(rev.split('.')[-2:]) in ('yandex.ru', 'yandex.net', 'yandex.com') and \
               socket.gethostbyname(rev) == self.cur_addr

    @property
    def _is_google_bot(self):
        rev = ''
        try:
            rev = socket.gethostbyaddr(self.cur_addr)[0]
        except socket.herror:
            pass
        return '.'.join(rev.split('.')[-2:]) in ('googlebot.com', 'google.com') and \
               socket.gethostbyname(rev) == self.cur_addr

    @score(2)
    def if_too_high_rps(self):
        """1 и более запрос в секунду"""
        it = self.cur_req
        reqs_total = len(it.timestamps)
        rps = reqs_total / ((it.timestamps[-1] - it.timestamps[0]) or self.interval)
        return rps >= 1 and reqs_total > 2

    @score(2)
    def if_too_low_intervals(self):
        """мода множества интервалов между запросами меньше или равна 1с;
        если множество мультимодально, то медиана меньше или равна 1с

        ( см. https://en.wikipedia.org/wiki/Mode_(statistics) ,
        https://en.wikipedia.org/wiki/Median )
        """
        it = self.cur_req
        intervals = [i - it.timestamps[idx-1] for idx, i in enumerate(it.timestamps) if idx > 0]
        if not intervals: return False
        try:
            return statistics.mode(intervals) <= 1
        except statistics.StatisticsError:
            return statistics.median_grouped(intervals) <= 1

    @score(3)
    def if_empty_user_agent(self):
        """пустой User-Agent"""
        return self.cur_req.user_agents == set(('-'))

    @score(5)
    def if_majordomo_ru_requested(self):
        """обращение к *.majordomo.ru"""
        return 'majordomo.ru' in ('.'.join(h.split('.')[-2:]) for h in self.cur_req.hosts)

    @score(3)
    def if_empty_host(self):
        """пустой Host"""
        return not self.cur_req.hosts

    @score(-1)
    def if_different_user_agents(self):
        """запросы с различными User-Agent"""
        return len(self.cur_req.user_agents) > 1

    @score(1)
    def if_requests_from_same_23_orlonger_network(self):
        """найдены похожие запросы с IP адресов в одной сети c префиксом /23 или длиннее
        (согласно whois.cymru.com)"""
        if not self.ip_sameorigin_count: self._fill_ip_sameorigin_count(min_len=23)
        return self.ip_sameorigin_count.get(self.cur_addr, 0) > 1

    @score(-1)
    def if_russian_address(self):
        """запросы с территории РФ"""
        return self.cur_req.geo_country_name == 'Russia'

    @score(2)
    def if_hosts_with_same_first_2_chars(self):
        """одинаковые первые два символа в различных Host, перебор доменов по алфавиту"""
        domains = {bytes('.'.join(h.split('.')[-2:]), 'idna').decode('idna') for h in self.cur_req.hosts}
        return len(domains) > 1 and len({d[:2] for d in domains}) == 1

    @score(-5)
    def if_yandex_bot(self):
        """бот Яндекса"""
        if not 'yandex.com/bot' in ''.join(self.cur_req.user_agents): return False
        return self._is_yandex_bot

    @score(-5)
    def if_google_bot(self):
        """бот Google"""
        if not 'google.com/bot' in ''.join(self.cur_req.user_agents): return False
        return self._is_google_bot

    @score(3)
    def if_fraud_yandex_bot(self):
        """поддельный бот Яндекса"""
        return 'yandex.com/bot' in ''.join(self.cur_req.user_agents) and not self._is_yandex_bot

    @score(3)
    def if_fraud_google_bot(self):
        """поддельный бот Google"""
        return 'google.com/bot' in ''.join(self.cur_req.user_agents) and not self._is_google_bot

    @score(1)
    def if_same_request_size(self):
        """более 10 запросов, и все запросы имеют одинаковый размер в байтах"""
        return len(self.cur_req.timestamps) > 10 and len(self.cur_req.req_sizes) == 1

    @score(-5)
    def if_from_cloudflare(self):
        """запрос с CloudFlare"""
        return any((IPv4Address(self.cur_addr) in IPv4Network(n) for n in ('103.21.244.0/22',
                                                                           '103.22.200.0/22',
                                                                           '103.31.4.0/22',
                                                                           '104.16.0.0/12',
                                                                           '108.162.192.0/18',
                                                                           '131.0.72.0/22',
                                                                           '141.101.64.0/18',
                                                                           '162.158.0.0/15',
                                                                           '172.64.0.0/13',
                                                                           '173.245.48.0/20',
                                                                           '188.114.96.0/20',
                                                                           '190.93.240.0/20',
                                                                           '197.234.240.0/22',
                                                                           '198.41.128.0/17')))

    @score(-2)
    def if_referer_contains_host(self):
        """Host и netloc в Referer совпадают"""
        return self.cur_req.hosts == set(parse.urlparse(r).netloc for r in self.cur_req.referers)

    @score(2)
    def if_wordpress_bruteforce(self):
        """запросы исключительно к /wp-login.php и /xmlrpc.php более, чем одного Host"""
        return len(self.cur_req.hosts) > 1 and \
               set(p.lstrip('/') for p in self.cur_req.paths) == {'wp-login.php', 'xmlrpc.php'}
