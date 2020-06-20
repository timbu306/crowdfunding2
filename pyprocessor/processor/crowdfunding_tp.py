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
        try:
            tierName = payload_list[2]
        except:
            LOGGER.info("no tierName submitted")
        # Get the public key sent from the client.
        from_key = header.signer_public_key

        # Perform the operation.
        LOGGER.info("Operation = "+ operation)

        if operation == "createcampaign":
            self._make_createcampaign(context, amount, from_key)
        elif operation == "deposit":
            self._make_deposit(context, amount, from_key)
        elif operation == "createtier":
            self._make_createtier(contexsawtooth.hyperledger.org/t, amount, tierName, from_key)
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
            LOGGER.info('No previous minamount, creating new minamount {} '
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

    def _make_deposit(self, context, amount, from_key):
        wallet_address = self._get_wallet_address(from_key)
        totalbalance = 0
        if (int(amount) <= 0):
            LOGGER.info('amount cant be less than 0')
        else:
            LOGGER.info('Got the key {} and the wallet address {} '.format(
                from_key, wallet_address))
            enc_dict_statedata = context.get_state([wallet_address])
            LOGGER.info(enc_dict_statedata)
            dec_dict_statedata = json.loads(enc_dict_statedata[0].data.decode('utf-8'))
            LOGGER.info(type(dec_dict_statedata))

            if from_key in dec_dict_statedata.keys(): dec_dict_statedata[from_key]+= int(amount)
            else: dec_dict_statedata[from_key] = int(amount)
            enc_dict=json.dumps(dec_dict_statedata).encode('utf-8')
            _=context.set_state({wallet_address: enc_dict})

            LOGGER.info(dec_dict_statedata)

        """ dec_dict_statedata[context] += amount
            LOGGER.info(dec_dict_statedata)

            if from_key in dec_dict_statedata:
                LOGGER.info('there is no balance yet')
                dec_dict_statedata[from_key] = amount
            else:
                balance = dec_dict_statedata[from_key]
                LOGGER.info('old balance = ' + balance)
                dec_dict_statedata[from_key] = balance + amount1

            LOGGER.info('new balance = ' + dec_statedata[from_key])
            enc_statedata = json.dumps(dec_statedata).encode('utf-8')
            addresses = context.set_state(
                {self._get_wallet_address(from_key): enc_statedata})
            for key in dec_statedata:
                totalbalance = totalbalance + dec_statedata[key]
            minamount = dec_statedata[minamount]
            if (totalbalance >= minamount):
                LOGGER.info('Crowdfunding Project founded!')
"""
    def _make_createtier(self, context, amount, tierName, from_key):
        LOGGER.info('creating a new Tier: ' + ' amount: ' + str(amount) +
            ' tierName: ' +str(tierName) + ' from_key: ' + str(from_key))
        wallet_address = self._get_wallet_address(from_key)
        LOGGER.info('Got the key {} and the wallet address {} '.format(
            from_key, wallet_address))
        encoded_entry = context.get_state([wallet_address])
        decoded_entry = pickle.loads(encoded_entry.decode('base64', 'strict'))
        decoded_entry[tierName] = amount
        LOGGER.info(decoded_entry)

    def _decode_data(self, data):
        return data.decode().split(',')

    def _encode_data(self, data):
        return ','.join(data).encode()

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
        current_entry = context.get_state([wallet_address])
        current_entry_to = context.get_state([wallet_to_address])
        new_balance = 0

        if current_entry == []:
            LOGGER.info('No user (debtor) with the key {} '.format(from_key))
        if current_entry_to == []:
            LOGGER.info('No user (creditor) with the key {} '.format(to_key))

        balance = int(current_entry[0].data)
        balance_to = int(current_entry_to[0].data)
        if balance < transfer_amount:
            raise InvalidTransaction('Not enough money. ' +
                'The amount should be less or equal to {} '.format(balance))
        else:
            LOGGER.info("Debiting balance with {}".format(transfer_amount))
            update_debtor_balance = balance - int(transfer_amount)
            state_data = str(update_debtor_balance).encode('utf-8')
            context.set_state({wallet_address: state_data})
            update_beneficiary_balance = balance_to + int(transfer_amount)
            state_data = str(update_beneficiary_balance).encode('utf-8')
            context.set_state({wallet_to_address: state_data})

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
