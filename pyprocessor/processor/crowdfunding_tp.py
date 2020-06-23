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
Transaction family class for simplewallet.
'''
import json
import traceback
import sys
import hashlib
import logging

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = "crowdfunding"

def _hash(data):
    '''Compute the SHA-512 hash and return the result as hex characters.'''
    return hashlib.sha512(data).hexdigest()

# Prefix for simplewallet is the first six hex digits of SHA-512(TF name).
sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]

class CrowdFundingTransactionHandler(TransactionHandler):
    '''
    Transaction Processor class for the simplewallet transaction family.

    This with the validator using the accept/get/set functions.
    It implements functions to deposit, withdraw, and transfer money.
    '''

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [self._namespace_prefix]

    def apply(self, transaction, context):
        '''This implements the apply function for this transaction handler.

           This function does most of the work for this class by processing
           a single transaction for the simplewallet transaction family.
        '''

        # Get the payload and extract simplewallet-specific information.
        header = transaction.header
        payload_list = transaction.payload.decode().split(",")
        operation = payload_list[0]
        amount = payload_list[1]

        # Get the public key sent from the client.
        from_key = header.signer_public_key

        # Perform the operation.
        LOGGER.info("Operation = "+ operation)

        if operation == "createcampaign":
            self._make_createcampaign(context, amount, from_key)
        elif operation == "deposit":
            self._make_deposit(context, amount, from_key)
        elif operation == "evaluate":
            self._make_evaluate(context, from_key)
        elif operation == "createtier":
            if len(payload_list) == 3:
                tierName = payload_list[2]
            self._make_createtier(context, amount, tierName, from_key)
        elif operation == "withdraw":
            self._make_withdraw(context, amount, from_key)
        elif operation == "transfer":
            if len(payload_list) == 3:
                to_key = payload_list[2]
            self._make_transfer(context, amount, to_key, from_key)
        else:
            LOGGER.info("Unhandled action. " +
                "Operation should be deposit, createcampaign, createTier, withdraw or transfer")

    def _make_createcampaign(self, context, amount, from_key):
        wallet_address = self._get_wallet_address(from_key)
        LOGGER.info('Got the key {} and the wallet address {} '.format(
            from_key, wallet_address))
        current_entry = context.get_state([wallet_address])

        if current_entry == []:
            LOGGER.info('No previous min_amount, creating new minamount {} '
                .format(from_key))

            dict_statedata = {}
            minamount = 'min_amount'
            amount1 = int(amount)
            dict_statedata[minamount] = amount1
            enc_dict_statedata = json.dumps(dict_statedata).encode('utf-8')
            LOGGER.info(type(enc_dict_statedata))
            addresses = context.set_state({wallet_address: enc_dict_statedata})
            if len(addresses) < 1:
                raise InternalError("State Error")
        else:
            raise InvalidTransaction('Campaign with address {} already exists '
                .format(from_key))

    def _make_evaluate(self, context, from_key):
        camp_balance = 0
        tier_dict = {}
        tier_list = []
        tier_founder_dict ={}
        founder_dict= {}

        wallet_address = self._get_wallet_address(from_key)
        LOGGER.info('Got the key {} and the wallet address {} '.format(from_key, wallet_address))
        enc_dict_statedata = context.get_state([wallet_address])

        if (len(enc_dict_statedata) == 0):
            raise InvalidTransaction("No Campaign on the address: " + str(wallet_address))
        else:
            dec_dict_statedata = json.loads(enc_dict_statedata[0].data.decode('utf-8'))

        LOGGER.info("dec_dict_statedata= " + str(dec_dict_statedata))
        min_amount = dec_dict_statedata['min_amount']
        LOGGER.info("Minimum amount needed before funding= " + str(min_amount))
        keylist = list(dec_dict_statedata.keys())

        for key, value in dec_dict_statedata.items():
            if (len(key) < 15 ) and (key != 'min_amount'):
                tier_dict[key] = value
            elif (key != 'min_amount'):
                founder_dict[key] = value

        LOGGER.info("founder_dict= " + str(founder_dict))
        LOGGER.info("tier_dict = " + str(tier_dict))

        for key in founder_dict.keys():
            if (len(key) > 15 ):
                camp_balance += founder_dict[key]
        LOGGER.info("Campaign has a balance of: " + str(camp_balance))

        if camp_balance >= min_amount:
            LOGGER.info("Campaign sucessufully founded!")
        else:
            LOGGER.info("Campaign has not been sucessufully founded!")

        for key, value in tier_dict.items():
            for key2, value2 in founder_dict.items():
                if (value2 >= value):
                    tier_list.append(key2)

            LOGGER.info("Tier: " + key + " has been reached by addresses: " + str(tier_list))
            tier_founder_dict[key] = tier_list
            tier_list.clear()

        LOGGER.info("tier_dict_addresses: " + str(tier_founder_dict))


    def _make_deposit(self, context, amount, from_key):
        wallet_address = self._get_wallet_address(from_key)
        if (int(amount) <= 0):
            raise InvalidTransaction("The amount cannot be <= 0")

        LOGGER.info('Got the key {} and the wallet address {} '.format(from_key, wallet_address))

        enc_dict_statedata = context.get_state([wallet_address])
        LOGGER.info(type(enc_dict_statedata))
        LOGGER.info(str(enc_dict_statedata))
        if (len(enc_dict_statedata) == 0):
            dec_dict_statedata = {}
            dec_dict_statedata[from_key] = int(amount)

        else:
            dec_dict_statedata = json.loads(enc_dict_statedata[0].data.decode('utf-8'))
            if (from_key in dec_dict_statedata.keys()):
                LOGGER.info('Account has balance already, adding')
                dec_dict_statedata[from_key]+= int(amount)
            else:
                LOGGER.info('Account has no balance yet')
                dec_dict_statedata[from_key] = int(amount)

        LOGGER.info(dec_dict_statedata)
        enc_dict=json.dumps(dec_dict_statedata).encode('utf-8')
        _=context.set_state({wallet_address: enc_dict})

    def _make_createtier(self, context, amount, tierName, from_key):
        LOGGER.info('creating a new Tier: ' + ' amount: ' + str(amount) +
            ' tierName: ' +str(tierName) + ' from_key: ' + str(from_key))
        wallet_address = self._get_wallet_address(from_key)
        enc_dict_statedata = context.get_state([wallet_address])
        if (len(enc_dict_statedata) == 0):
            raise InvalidTransaction("This account is empty, create campaign first")
        dec_dict_statedata = json.loads(enc_dict_statedata[0].data.decode('utf-8'))
        if not ('min_amount' in dec_dict_statedata):
            raise InvalidTransaction("This Account has no Campaign, Create campaign first!")
        if ( len(tierName) > 15 or len(tierName) < 1 ):
            LOGGER.info('tierName must be between 1 and 10 characters long, tierName length: ' + str(len(tierName)))
        elif (tierName in dec_dict_statedata.keys()):
            LOGGER.info('Tier already exists in this campaign use different name')
        else:
            dec_dict_statedata[tierName] = int(amount)
            LOGGER.info(dec_dict_statedata)
            enc_dict=json.dumps(dec_dict_statedata).encode('utf-8')
            _=context.set_state({wallet_address: enc_dict})

    def _make_transfer(self, context, transfer_amount, to_key, from_key):
        transfer_amount = int(transfer_amount)
        if transfer_amount <= 0:
            raise InvalidTransaction("The amount cannot be <= 0")

        wallet_address = self._get_wallet_address(from_key)
        wallet_to_address = self._get_wallet_address(to_key)
        LOGGER.info('Got the from key {} and the from wallet address {} '.format(
            from_key, wallet_address))
        LOGGER.info('Got the to key {} and the to wallet address {} '.format(
            to_key, wallet_to_address))
        enc_dict_statedata_from = context.get_state([wallet_address])
        enc_dict_statedata_to = context.get_state([wallet_to_address])
        new_amount = 0
        old_amount = 0

        if (len(enc_dict_statedata_from) == 0):
            raise InvalidTransaction('Sender Account has no Balance yet')

        if (len(enc_dict_statedata_to) == 0):
            raise InvalidTransaction('Receiver Account has no Balance yet')

        dec_dict_statedata_from = json.loads(enc_dict_statedata_from[0].data.decode('utf-8'))
        dec_dict_statedata_to = json.loads(enc_dict_statedata_to[0].data.decode('utf-8'))
        LOGGER.info('dec_dict_statedata_to: ' + str(dec_dict_statedata_to))
        if (from_key in dec_dict_statedata_to):
            old_amount = dec_dict_statedata_to[from_key]
        new_amount = old_amount + transfer_amount
        dec_dict_statedata_from[from_key] = int(dec_dict_statedata_from[from_key] - transfer_amount)
        dec_dict_statedata_to[from_key] = new_amount
        if dec_dict_statedata_from[from_key] <0 :
            raise InvalidTransaction("Sender account has not enough balance")

        if not ('min_amount' in dec_dict_statedata_to):
            raise InvalidTransaction("Can only transfer money to a campaign")

        LOGGER.info('new state data sender: ' + str(dec_dict_statedata_from))
        LOGGER.info('new state data receiver: ' + str(dec_dict_statedata_to))
        enc_dict_from=json.dumps(dec_dict_statedata_from).encode('utf-8')
        _=context.set_state({wallet_address: enc_dict_from})
        enc_dict_to=json.dumps(dec_dict_statedata_to).encode('utf-8')
        _=context.set_state({wallet_to_address: enc_dict_to})

    def _get_wallet_address(self, from_key):
        return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + _hash(from_key.encode('utf-8'))[0:64]


def setup_loggers():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)

def main():
    '''Entry-point function for the simplewallet transaction processor.'''
    setup_loggers()
    try:
        # Register the transaction handler and start it.
        processor = TransactionProcessor(url='tcp://validator:4004')

        handler = CrowdFundingTransactionHandler(sw_namespace)

        processor.add_handler(handler)

        processor.start()

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
