import logging
import hashlib

import cbor

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError


LOGGER = logging.getLogger(__name__)


VALID_VERBS = 'set', 'inc', 'dec', 'transfer' # 'transfer' verb added

MIN_VALUE = 0
MAX_VALUE = 4294967295
MAX_NAME_LENGTH = 20

FAMILY_NAME = 'modified_intkey'

ADDRESS_PREFIX = hashlib.sha512(
    FAMILY_NAME.encode('utf-8')).hexdigest()[0:6]


def make_address(name):
    return ADDRESS_PREFIX + hashlib.sha512(
        name.encode('utf-8')).hexdigest()[-64:]


class ModifiedTransactionHandler(TransactionHandler):
    # Disable invalid-overridden-method. The sawtooth-sdk expects these to be
    # properties.
    # pylint: disable=invalid-overridden-method
    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [ADDRESS_PREFIX]

    def apply(self, transaction, context):
        verb, name, value, receiver = _unpack_transaction(transaction)

        state = _get_state_data(name, context)

        updated_state = _do_modified_intkey(verb, name, value, receiver, state)

        _set_state_data(name, updated_state, context)


def _unpack_transaction(transaction):
    verb, name, value, receiver = _decode_transaction(transaction)

    _validate_verb(verb)
    _validate_name(name)
    _validate_value(value)
    _validate_receiver(verb, receiver) 

    return verb, name, value, receiver


def _decode_transaction(transaction):
    try:
        content = cbor.loads(transaction.payload)
    except Exception as e:
        raise InvalidTransaction('Invalid payload serialization') from e

    try:
        verb = content['Verb']
    except AttributeError:
        raise InvalidTransaction('Verb is required') from AttributeError

    try:
        name = content['Name']
    except AttributeError:
        raise InvalidTransaction('Name is required') from AttributeError

    try:
        value = content['Value']
    except AttributeError:
        raise InvalidTransaction('Value is required') from AttributeError

    if verb == "transfer":
        try:
            receiver = content['Receiver']
        except AttributeError:
            raise InvalidTransaction('Receiver is required')
    else:
        receiver = ""

    return verb, name, value, receiver


def _validate_verb(verb):
    if verb not in VALID_VERBS:
        raise InvalidTransaction('Verb must be "set", "inc" or "dec"')


def _validate_name(name):
    if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH:
        raise InvalidTransaction(
            'Name must be a string of no more than {} characters'.format(
                MAX_NAME_LENGTH))


def _validate_value(value):
    if not isinstance(value, int) or value < 0 or value > MAX_VALUE:
        raise InvalidTransaction(
            'Value must be an integer '
            'no less than {min} and no greater than {max}'.format(
                min=MIN_VALUE,
                max=MAX_VALUE))


# checks required if the verb is receiver 
def _validate_receiver(verb, receiver):
    if verb == 'transfer':
        if receiver == "":
            raise InvalidTransaction('Receiver cannot be empty')
    else:
        if receiver != "":
            raise InvalidTransaction('Receiver needs to be empty')



def _get_state_data(name, context):
    address = make_address(name)

    state_entries = context.get_state([address])

    try:
        return cbor.loads(state_entries[0].data)
    except IndexError:
        return {}
    except Exception as e:
        raise InternalError('Failed to load state data') from e


def _set_state_data(name, state, context):
    address = make_address(name)

    encoded = cbor.dumps(state)

    addresses = context.set_state({address: encoded})

    if not addresses:
        raise InternalError('State error')


def _do_modified_intkey(verb, name, value, receiver, state):
    verbs = {
        'set': _do_set,
        'inc': _do_inc,
        'dec': _do_dec,
        'transfer':_do_transfer,
    }

    try:
        return verbs[verb](name, value, receiver, state)
    except KeyError:
        # This would be a programming error.
        raise InternalError('Unhandled verb: {}'.format(verb)) from KeyError

def _do_set(name, value, receiver, state):
    msg = 'Setting "{n}" to {v}'.format(n=name, v=value)
    LOGGER.debug(msg)

    if name in state:
        raise InvalidTransaction(
            'Verb is "set", but already exists: Name: {n}, Value {v}'.format(
                n=name,
                v=state[name]))

    updated = dict(state.items())
    updated[name] = value

    return updated


def _do_inc(name, value, receiver, state):
    msg = 'Incrementing "{n}" by {v}'.format(n=name, v=value)
    LOGGER.debug(msg)

    if name not in state:
        raise InvalidTransaction(
            'Verb is "inc" but name "{}" not in state'.format(name))

    curr = state[name]
    incd = curr + value

    if incd > MAX_VALUE:
        raise InvalidTransaction(
            'Verb is "inc", but result would be greater than {}'.format(
                MAX_VALUE))

    updated = dict(state.items())
    updated[name] = incd

    return updated


def _do_dec(name, value, receiver, state):
    msg = 'Decrementing "{n}" by {v}'.format(n=name, v=value)
    LOGGER.debug(msg)

    if name not in state:
        raise InvalidTransaction(
            'Verb is "dec" but name "{}" not in state'.format(name))

    curr = state[name]
    decd = curr - value

    if decd < MIN_VALUE:
        raise InvalidTransaction(
            'Verb is "dec", but result would be less than {}'.format(
                MIN_VALUE))

    updated = dict(state.items())
    updated[name] = decd

    return updated

def _do_transfer(verb, name, value, receiver, state):
    msg = 'Transfering "{v}" from "{n}" to "{r}"'.format(v=value, n=name, r=receiver)
    LOGGER.debug(msg)

    if name not in state:
        raise InvalidTransaction('Verb is "transfer" but name "{}" not in state'.format(name))

    if receiver not in state:
        raise InvalidTransaction('Verb is "transfer" but receiver "{}" not in state'.format(receiver))

    send = state[name]
    transfer_from = send - value

    if transfer_from < MIN_VALUE:
        raise InvalidTransaction('Verb is "transfer", but result would be less than {}'.format(
                MIN_VALUE))

    receive = state[receiver]
    transfer_to = receive + value

    if transfer_to > MAX_VALUE:
        raise InvalidTransaction('Verb is "transfer", but result would be greater than {}'.format(
                MAX_VALUE))
    
    updated = dict(state.items())
    updated[name] = transfer_from
    updated[receiver] = transfer_to

    return updated