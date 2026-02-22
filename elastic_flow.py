import argparse
import csv
import json
import os
import sys
import getpass
import logging
import requests
import urllib3

# Default configuration values
DEFAULT_ES_URL = os.environ.get('ES_URL', 'https://your-elastiflow-server:9200')
DEFAULT_INDEX = os.environ.get('ES_INDEX', 'elastiflow-*')
DEFAULT_INPUT_CSV = os.environ.get('INPUT_CSV', 'source_subnets.csv')
DEFAULT_OUTPUT_CSV = os.environ.get('OUTPUT_CSV', 'destination_ips.csv')

# Elastiflow field names (Standard ECS format)
SRC_FIELD = os.environ.get('SRC_FIELD', 'source.ip')
DST_FIELD = os.environ.get('DST_FIELD', 'destination.ip')

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


def load_subnets(path):
    subnets = []
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                subnets.append(row[0].strip())
    return subnets


def build_payload(subnets, days=14, agg_size=10000):
    subnet_query_string = ' OR '.join(f'"{subnet}"' for subnet in subnets)
    payload = {
        'size': 0,
        'query': {
            'bool': {
                'filter': [
                    {'range': {'@timestamp': {'gte': f'now-{days}d/d', 'lte': 'now/d'}}},
                    {'query_string': {'default_field': SRC_FIELD, 'query': subnet_query_string}}
                ]
            }
        },
        'aggs': {'unique_destinations': {'terms': {'field': DST_FIELD, 'size': agg_size}}}
    }
    return payload


def confirm(prompt):
    try:
        resp = input(prompt + " [y/N]: ").strip().lower()
    except EOFError:
        return False
    return resp in ('y', 'yes')


def main():
    parser = argparse.ArgumentParser(description='Safe Elastiflow destination extractor')
    parser.add_argument('--es-url', default=DEFAULT_ES_URL, help='Elasticsearch API URL')
    parser.add_argument('--index', default=DEFAULT_INDEX, help='Index or index pattern to query')
    parser.add_argument('--username', default=os.environ.get('ES_USERNAME'), help='ES username (or set ES_USERNAME)')
    parser.add_argument('--password', default=os.environ.get('ES_PASSWORD'), help='ES password (or set ES_PASSWORD)')
    parser.add_argument('--input', default=DEFAULT_INPUT_CSV, help='Input CSV with subnets')
    parser.add_argument('--output', default=DEFAULT_OUTPUT_CSV, help='Output CSV file')
    parser.add_argument('--days', type=int, default=14, help='Lookback window in days')
    parser.add_argument('--size', type=int, default=10000, help='Max unique destinations to return')
    parser.add_argument('--timeout', type=int, default=30, help='HTTP timeout in seconds')
    parser.add_argument('--insecure', action='store_true', help='Allow insecure SSL (skip cert verification)')
    parser.add_argument('--allow-wildcard', action='store_true', help='Allow wildcard/index patterns like elastiflow-*')
    parser.add_argument('--dry-run', action='store_true', help='Do not query ES; just print the payload and exit')
    parser.add_argument('--confirm', action='store_true', help='Automatically confirm any prompts')
    args = parser.parse_args()

    # Basic sanity checks
    if '*' in args.index and not args.allow_wildcard:
        logging.error('Index contains wildcard. Re-run with --allow-wildcard to proceed intentionally.')
        sys.exit(2)

    username = args.username
    password = args.password
    if username and not password:
        password = getpass.getpass('Elasticsearch password: ')
    if not username or not password:
        logging.error('Missing Elasticsearch credentials. Provide --username/--password or set ES_USERNAME/ES_PASSWORD.')
        sys.exit(2)

    if not os.path.exists(args.input):
        logging.error('Input CSV not found: %s', args.input)
        sys.exit(2)

    subnets = load_subnets(args.input)
    logging.info('Loaded %d subnets from %s', len(subnets), args.input)

    payload = build_payload(subnets, days=args.days, agg_size=args.size)

    # Dry-run prints payload only (safe)
    if args.dry_run:
        print('DRY RUN: ES URL:', args.es_url)
        print('DRY RUN: Index:', args.index)
        print(json.dumps(payload, indent=2))
        logging.info('Dry-run complete. No requests were sent to Elasticsearch.')
        return

    # If the target is a broad/wildcard index, require confirmation unless --confirm was passed
    if '*' in args.index and not args.confirm:
        if not confirm(f"Index '{args.index}' contains a wildcard. Proceed with query?"):
            logging.info('Aborted by user.')
            sys.exit(0)

    # Handle SSL verification
    verify = not args.insecure
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {'Content-Type': 'application/json'}

    url = f"{args.es_url.rstrip('/')}/{args.index}/_search"
    logging.info('Querying Elasticsearch at %s', url)

    try:
        resp = requests.post(url, auth=(username, password), headers=headers,
                             data=json.dumps(payload), verify=verify, timeout=args.timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error('Request to Elasticsearch failed: %s', e)
        sys.exit(1)

    try:
        data = resp.json()
    except ValueError:
        logging.error('Failed to decode JSON response from Elasticsearch')
        sys.exit(1)

    buckets = data.get('aggregations', {}).get('unique_destinations', {}).get('buckets', [])

    try:
        with open(args.output, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Destination IP', 'Flow Count'])
            for bucket in buckets:
                writer.writerow([bucket.get('key'), bucket.get('doc_count')])
    except OSError as e:
        logging.error('Failed to write output CSV: %s', e)
        sys.exit(1)

    logging.info('Success: exported %d unique destination IPs to %s', len(buckets), args.output)


if __name__ == '__main__':
    main()