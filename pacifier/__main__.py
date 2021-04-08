#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import logging
import requests
import signal
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor
from elasticsearch.helpers import scan
from elasticsearch import Elasticsearch
from pythonjsonlogger import jsonlogger

from pacifier.checklist import CMSBrute


CHECK_INTERVAL = 120
ES_HOST = 'es.intr'
ES_INDEX_TEMPLATE = 'nginx-%Y.%m.%d'
ES_QUERY_CMS_BRUTE = '(path:xmlrpc.php OR path:administrator.php OR path:wp-login.php OR path:admin OR path:wp-admin) AND method:POST AND NOT code:301'
MIN_SCORE = 3
URL_TEMPLATE = 'http://{}.intr/ip-filter'
FILTER_ACTION = 'setCookie'
LOG_LEVEL = logging.INFO
BLOCK_TIME_DEFAULT = 600  # seconds
BLOCK_TIME_MULTIPLIER = 100  # seconds
BLOCK_TIME_TTL = 60 * 60 * 4  # seconds
BLOCK_TIME_TTL_MAX = 7200  # seconds defined in webservices/nginx/lua/filter_api.lua

# parameter, e.g: {"172.16.103.176": {"count": 1, "last_block_time": 1605263045.2532582}, ...}
bad_guys_remember = {}


def get_nginx_hosts():
    return os.environ.get("PACIFER_MONITORING_HOSTS").strip().split(",")


def find_bad_guys(es_host, es_index_template, es_query, interval, min_score):
    es = Elasticsearch(es_host)
    index = datetime.datetime.utcnow().date().strftime(es_index_template)
    q = {'query': {
            'bool': {
                'must_not': [
                    {
                        'exists': {
                            'field': 'remote_user'
                        }
                    }
                ],
                'must': [
                    {
                        'query_string': {
                            'query': es_query,
                            'analyze_wildcard': True,
                            'default_field': '*'
                        }
                    },
                    {
                        'range': {
                            '@timestamp': {
                                'gte': int(round(time.time() * 1000)) - interval * 1000,
                                'format': 'epoch_millis',
                                'lte': int(round(time.time() * 1000))
                            }
                        }
                    }
                ]
            }
        }
    }
    cms_brute = CMSBrute(interval, min_score)
    for each in scan(es, query=q, index=index):
        source = each.get('_source')
        addr = source.get('remote_addr')
        if not addr: continue
        cms_brute.add_data(addr, source)
    return cms_brute.check()


def ban_bad_guys(hosts, addrs, interval, action, url_template):
    if not addrs: return

    def format_post(ip):
        """
        Проверить наличие IP адреса в словаре и если есть то увеличить интервал блокировки
        """
        global bad_guys_remember
        if bad_guys_remember and ip in bad_guys_remember.keys():
            bad_guys_remember[ip]["count"] += 1
            bad_guys_remember[ip]["last_block_time"] = time.time()
            increased_interval = interval + bad_guys_remember[ip]["count"] * BLOCK_TIME_MULTIPLIER
            return '{} {} {}'.format(
                ip,
                increased_interval if bad_guys_remember[ip]["count"] > 1 and increased_interval <= BLOCK_TIME_TTL_MAX else interval,
                action
            )
        else:
            bad_guys_remember[ip] = {"count": 1, "last_block_time": time.time()}
            return '{} {} {}'.format(ip, interval, action)

    post_data = '\n'.join(map(format_post, addrs)) + '\n'
    with ThreadPoolExecutor(max_workers=len(hosts)) as executor:
        executor.map(lambda p: requests.post(*p, timeout=3), ((url_template.format(h), post_data) for h in hosts))


def setup_logger(level):
    logger = logging.getLogger()
    es_logger = logging.getLogger('elasticsearch')
    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter(fmt='%(asctime)%(levelname)%(message)', json_ensure_ascii=False))
    logger.addHandler(handler)
    logger.setLevel(level)
    es_logger.addHandler(handler)
    es_logger.setLevel(logging.WARN)


def handle_sigterm(_, __):
    logging.info('SIGTERM received, shutting down')
    sys.exit(0)


def handle_sigusr1(_, __):
    if logging.getLogger().getEffectiveLevel() == LOG_LEVEL:
        setup_logger(logging.DEBUG)
    else:
        setup_logger(LOG_LEVEL)


def main():
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGUSR1, handle_sigusr1)
    setup_logger(LOG_LEVEL)
    hosts = get_nginx_hosts()
    while True:
        try:
            start = time.time()

            # Clean up bad_guys_remember.
            for ip in list(bad_guys_remember.keys()):
                if bad_guys_remember[ip]["last_block_time"] < (time.time() - BLOCK_TIME_TTL):
                    bad_guys_remember.pop(ip)

            bad_guys = find_bad_guys(ES_HOST, ES_INDEX_TEMPLATE, ES_QUERY_CMS_BRUTE, CHECK_INTERVAL, MIN_SCORE)
            bad_guys.extend(find_bad_guys(ES_HOST, ES_INDEX_TEMPLATE, ES_QUERY_CMS_BRUTE, CHECK_INTERVAL * 30, MIN_SCORE))
            ban_bad_guys(hosts, set((e['address'] for e in bad_guys)), BLOCK_TIME_DEFAULT, FILTER_ACTION, URL_TEMPLATE)
            for each in bad_guys:
                logging.info('{} added to filters'.format(each['address']), extra=each)
            time.sleep(max(0, CHECK_INTERVAL - (time.time() - start)))
        except Exception as e:
            logging.exception(e)


if __name__ == '__main__':
    main()
