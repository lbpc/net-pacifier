#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import requests
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from elasticsearch.helpers import scan
from elasticsearch import Elasticsearch
from pythonjsonlogger import jsonlogger

from checklist import CMSBrute


CHECK_INTERVAL = 600
ES_HOST = 'es.intr'
ES_INDEX_TEMPLATE = 'nginx-%Y.%m.%d' 
ES_QUERY = '(path:xmlrpc.php OR path:administrator.php OR path:wp-login.php) AND method:POST AND NOT code:301'
MIN_SCORE = 3
URL_TEMPLATE = 'http://{}.intr/ip-filter'
FILTER_ACTION = 'setCookie'


def get_nginx_hosts(es_host, es_index_template):
    es = Elasticsearch(es_host)
    index = date.today().strftime(es_index_template)
    return [b['key'].split('.')[0] for b in es.search(index=index, body={'size': 0,
                                                                         'aggs': {
                                                                             'hostnames': {
                                                                                 'terms': {
                                                                                     'field': 'hostname.keyword',
                                                                                     'size': 100
                                                                                 }
                                                                             }
                                                                         }
                                                                         })['aggregations']['hostnames']['buckets']]


def find_bad_guys(es_host, es_index_template, es_query, interval, min_score):
    es = Elasticsearch(es_host)
    index = date.today().strftime(es_index_template)
    q = {'query': {
            'bool': {
                'must': [
                    {'query_string': {
                        'query': es_query,
                        'analyze_wildcard': True,
                        'default_field': '*'
                    }
                    },
                    {'range': {
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
    post_data = '\n'.join(('{} {} {}'.format(a, interval, action) for a in addrs)) + '\n'
    with ThreadPoolExecutor(max_workers=len(hosts)) as executor:
        executor.map(lambda p: requests.post(*p), ((url_template.format(h), post_data) for h in hosts))


def handle_sigterm(_, __):
    logging.info('SIGTERM received, shutting down')
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, handle_sigterm)
    logger = logging.getLogger()
    es_logger = logging.getLogger('elasticsearch')
    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter(fmt='%(asctime)%(levelname)%(message)', json_ensure_ascii=False))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    es_logger.addHandler(handler)
    es_logger.setLevel(logging.WARN)
    while True:
        try:
            start = time.time()
            hosts = get_nginx_hosts(ES_HOST, ES_INDEX_TEMPLATE)
            bad_guys = find_bad_guys(ES_HOST, ES_INDEX_TEMPLATE, ES_QUERY, CHECK_INTERVAL, MIN_SCORE)
            bad_guys.extend(find_bad_guys(ES_HOST, ES_INDEX_TEMPLATE, ES_QUERY, CHECK_INTERVAL * 6, MIN_SCORE))
            ban_bad_guys(hosts, set((e['address'] for e in bad_guys)), CHECK_INTERVAL, FILTER_ACTION, URL_TEMPLATE)
            for each in bad_guys:
                logging.info('{} added to filters'.format(each['address']), extra=each)
            time.sleep(time.time() + CHECK_INTERVAL - start)
        except Exception as e:
            logging.exception(e)

if __name__ == '__main__':
    main()
