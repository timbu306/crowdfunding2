# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------
'''
CLI für die crowdfunding Transaction Family 
Parst Kommandozeilen Argumente zur SimpleWalletClient Klasse zur weiteren Verarbeitung.
'''

import argparse
import getpass
import logging
import os
import sys
import traceback
import pkg_resources

from colorlog import ColoredFormatter

from wallet.crowdfunding_client import CrowdFundingClient

DISTRIBUTION_NAME = 'crowdfunding'

DEFAULT_URL = 'http://rest-api:8008'

def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)
    clog.setLevel(logging.DEBUG)
    return clog

def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))

def add_evaluate_parser(subparsers, parent_parser):
    '''Define the "evaluate" command line parsing.'''
    parser = subparsers.add_parser(
    'evaluate',
	help='create an evaluation',
	parents=[parent_parser])

    parser.add_argument(
    'crowdfundingName',
    type=str,
    help= 'the name of the crowdfunding campaign')

def add_createcampaign_parser(subparsers, parent_parser):
    '''Define the "createcampaign" command line parsing.'''
    parser = subparsers.add_parser(
	'createcampaign',
	help='create a crowdfunding campaign',
	parents=[parent_parser])

    parser.add_argument(
	'value',
	type=int,
	help= 'the minimum amount for the campaign to succeed')

    parser.add_argument(
	'crowdfundingName',
	type=str,
	help= 'the name of the crowdfunding campaign')

def add_createtier_parser(subparsers, parent_parser):
    '''Define the "createTier" command line parsing.'''
    parser = subparsers.add_parser(
    'createtier',
    help='create a tier',
    parents=[parent_parser])

    parser.add_argument(
    'value',
    type = int,
    help= 'the minimum amount required for the Tier ')

    parser.add_argument(
    'tierName',
    type=str,
    help= 'the name of the Tier')

    parser.add_argument(
    'customerName',
    type=str,
    help= 'the name of the crowdfunding campaign')

def add_deposit_parser(subparsers, parent_parser):
    '''Define the "deposit" command line parsing.'''
    parser = subparsers.add_parser(
        'deposit',
        help='deposits a certain amount to an account',
        parents=[parent_parser])

    parser.add_argument(
        'value',
        type=int,
        help='the amount to deposit')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer to deposit to')

def add_withdraw_parser(subparsers, parent_parser):
    '''Define the "withdraw" command line parsing.'''
    parser = subparsers.add_parser(
        'withdraw',
        help='withdraws a certain amount from your account',
        parents=[parent_parser])

    parser.add_argument(
        'value',
        type=int,
        help='the amount to withdraw')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer to withdraw from')

def add_balance_parser(subparsers, parent_parser):
    '''Define the "balance" command line parsing.'''
    parser = subparsers.add_parser(
        'balance',
        help='shows balance in your account',
        parents=[parent_parser])

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer to withdraw from')

def add_transfer_parser(subparsers, parent_parser):
    '''Define the "transfer" command line parsing.'''
    parser = subparsers.add_parser(
        'transfer',
        help='transfers balance from one account to the other',
        parents=[parent_parser])

    parser.add_argument(
        'value',
        type=int,
        help='the amount to withdraw')

    parser.add_argument(
        'customerNameFrom',
        type=str,
        help='the name of customer to withdraw from')

    parser.add_argument(
        'customerNameTo',
        type=str,
        help='the name of customer to deposit to')

def create_parent_parser(prog_name):
    '''Define the -V/--version command line options.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    '''Define the command line parsing for all the options and subcommands.'''
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage your simple wallet',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    subparsers.required = True

    add_deposit_parser(subparsers, parent_parser)
    add_createcampaign_parser(subparsers, parent_parser)
    add_withdraw_parser(subparsers, parent_parser)
    add_balance_parser(subparsers, parent_parser)
    add_transfer_parser(subparsers, parent_parser)
    add_createtier_parser(subparsers, parent_parser)
    add_evaluate_parser(subparsers, parent_parser)

    return parser

def _get_keyfile(customerName):
    '''Get the private key for a customer.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, customerName)

def _get_pubkeyfile(customerName):
    '''Get the public key for a customer.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.pub'.format(key_dir, customerName)

def do_evaluate(args):
    '''Implements the "do_evaluate" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.crowdfundingName)

    client = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    response = client.evaluate(args.crowdfundingName)

    print("Response: {}".format(response))

def do_deposit(args):
    '''Implements the "deposit" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerName)

    client = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    response = client.deposit(args.value)

    print("Response: {}".format(response))

def do_createtier(args):
    '''Implements the "createtier" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerName)

    client = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    response = client.createtier(args.value, args.tierName)

    print("Response: {}".format(response))

def do_createcampaign(args):
    '''Implements the "createcampaign" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.crowdfundingName)

    client = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    response = client.createcampaign(args.value)

    print("Response: {}".format(response))

def do_withdraw(args):
    '''Implements the "withdraw" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerName)

    client = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    response = client.withdraw(args.value)

    print("Response: {}".format(response))

def do_balance(args):
    '''Implements the "balance" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerName)

    client = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    data = client.balance()

    if data is not None:
        print("\n{} has a net balance of = {}\n".format(args.customerName,
                                                        data.decode()))
    else:
        raise Exception("Data not found: {}".format(args.customerName))

def do_transfer(args):
    '''Implements the "transfer" subcommand by calling the client class.'''
    keyfileFrom = _get_keyfile(args.customerNameFrom)
    keyfileTo = _get_pubkeyfile(args.customerNameTo)

    clientFrom = CrowdFundingClient(baseUrl=DEFAULT_URL, keyFile=keyfileFrom)

    response = clientFrom.transfer(args.value, keyfileTo)
    print("Response: {}".format(response))

def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    '''Entry point function for the client CLI.'''
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    verbose_level = 0

    setup_loggers(verbose_level=verbose_level)

    # Get the commands from cli args and call corresponding handlers
    if args.command == 'deposit':
        do_deposit(args)
    elif args.command == 'withdraw':
        do_withdraw(args)
    elif args.command == 'evaluate':
        do_evaluate(args)
    elif args.command == 'createtier':
        do_createtier(args)
    elif args.command == 'balance':
        do_balance(args)
    elif args.command == 'createcampaign':
	    do_createcampaign(args)
    elif args.command == 'transfer':
        # Cannot deposit and withdraw from own account. noop.
        if args.customerNameFrom == args.customerNameTo:
            raise Exception("Cannot transfer money to self: {}"
                                        .format(args.customerNameFrom))

        do_transfer(args)
    else:
        raise Exception("Invalid command: {}".format(args.command))


def main_wrapper():
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
