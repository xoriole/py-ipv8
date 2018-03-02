from hashlib import sha256

import time

from ...keyvault.crypto import ECCrypto
from ...messaging.deprecated.encoding import decode, encode
from ...messaging.serialization import Serializer
from .payload import HalfBlockPayload


GENESIS_HASH = '0'*32    # ID of the first block of the chain.
GENESIS_SEQ = 1
UNKNOWN_SEQ = 0
EMPTY_SIG = '0'*64
EMPTY_PK = '0'*74


class TrustChainBlock(object):
    """
    Container for TrustChain block information
    """

    def __init__(self, data=None, serializer=Serializer()):
        super(TrustChainBlock, self).__init__()
        if data is None:
            # data
            self.transaction = {}
            # identity
            self.public_key = EMPTY_PK
            self.sequence_number = GENESIS_SEQ
            # linked identity
            self.link_public_key = EMPTY_PK
            self.link_sequence_number = UNKNOWN_SEQ
            # validation
            self.previous_hash = GENESIS_HASH
            self.signature = EMPTY_SIG
            # debug stuff
            self.insert_time = None
            # double signature
            self.double_signature = None
        else:
            _, self.transaction = decode(str(data[0]))
            (self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number, self.previous_hash,
             self.signature, self.insert_time) = (data[1], data[2], data[3], data[4], data[5], data[6], data[7])
            if isinstance(self.public_key, buffer):
                self.public_key = str(self.public_key)
            if isinstance(self.link_public_key, buffer):
                self.link_public_key = str(self.link_public_key)
            if isinstance(self.previous_hash, buffer):
                self.previous_hash = str(self.previous_hash)
            if isinstance(self.signature, buffer):
                self.signature = str(self.signature)
            # if self.transaction.startswith('64s'):
            #     self.double_signature = self.transaction[3:64]
        self.serializer = serializer

    @classmethod
    def from_payload(cls, payload, serializer):
        """
        Create a block according to a given payload and serializer.
        This method can be used when receiving a block from the network.
        """
        return cls([payload.transaction, payload.public_key, payload.sequence_number,
                    payload.link_public_key, payload.link_sequence_number, payload.previous_hash,
                    payload.signature, time.time()], serializer)

    @classmethod
    def from_pair_payload(cls, payload, serializer):
        """
        Create two half blocks from a block pair message, according to a given payload and serializer.
        Used to construct two blocks when receiving a block pair from the network.
        """
        block1 = cls([payload.transaction1, payload.public_key1, payload.sequence_number1,
                      payload.link_public_key1, payload.link_sequence_number1, payload.previous_hash1,
                      payload.signature1, time.time()], serializer)
        block2 = cls([payload.transaction2, payload.public_key2, payload.sequence_number2,
                      payload.link_public_key2, payload.link_sequence_number2, payload.previous_hash2,
                      payload.signature2, time.time()], serializer)
        return block1, block2

    def __str__(self):
        # This makes debugging and logging easier
        return "Block {0} from ...{1}:{2} links ...{3}:{4} for {5}".format(
            self.hash.encode("hex")[-8:],
            self.public_key.encode("hex")[-8:],
            self.sequence_number,
            self.link_public_key.encode("hex")[-8:],
            self.link_sequence_number,
            self.transaction)

    def __hash__(self):
        return self.hash

    def __eq__(self, other):
        if not isinstance(other, TrustChainBlock):
            return False
        return self.pack() == other.pack()

    @property
    def hash(self):
        return sha256(self.pack()).digest()

    @property
    def block_id(self):
        return "%s.%d" % (self.public_key.encode('hex'), self.sequence_number)

    @property
    def linked_block_id(self):
        return "%s.%d" % (self.link_public_key.encode('hex'), self.link_sequence_number)

    @property
    def hash_number(self):
        """
        Return the hash of this block as a number (used as crawl ID).
        """
        return int(self.hash.encode('hex'), 16) % 100000000L

    def pack(self, signature=True):
        """
        Encode this block for transport
        :param signature: False to pack EMPTY_SIG in the signature location, true to pack the signature field
        :return: the buffer the data was packed into
        """
        args = [self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number,
                self.previous_hash, self.signature if signature else EMPTY_SIG, self.transaction]
        return self.serializer.pack_multiple(HalfBlockPayload(*args).to_pack_list())

    def validate_transaction(self, database):
        """
        Validates the transaction of this block
        :param database: the database to check against
        :return: A tuple consisting of a ValidationResult and a list of user string errors
        """
        return ValidationResult.valid, []

    def validate(self, database):
        """
        Validates this block against what is known in the database
        :param database: the database to check against
        :return: A tuple consisting of a ValidationResult and a list of user string errors
        """

        # we start off thinking everything is hunky dory
        result = [ValidationResult.valid]
        errors = []
        crypto = ECCrypto()

        # short cut for invalidating so we don't have repeating similar code for every error.
        # this is also the reason result is a list, we need a mutable container. Assignments in err are limited to its
        # scope. So setting result directly is not possible.
        def err(reason):
            result[0] = ValidationResult.invalid
            errors.append(reason)

        # Step 1: get all related blocks from the database.
        # The validity of blocks is immutable. Once they are accepted they cannot change validation result. In such
        # cases subsequent blocks can get validation errors and will not get inserted into the database. Thus we can
        # assume that all retrieved blocks are not invalid themselves. Blocks can get inserted into the database in any
        # order, so we need to find successors, predecessors as well as the block itself and its linked block.
        blk = database.get(self.public_key, self.sequence_number)
        link = database.get_linked(self)
        prev_blk = database.get_block_before(self)
        next_blk = database.get_block_after(self)

        # Step 2: determine the maximum validation level
        # Depending on the blocks we get from the database, we can decide to reduce the validation level. We must do
        # this prior to flagging any errors. This way we are only ever reducing the validation level without having to
        # resort to min()/max() every time we set it. We first determine some booleans to make everything readable.
        is_genesis = self.sequence_number == GENESIS_SEQ or self.previous_hash == GENESIS_HASH
        is_prev_gap = prev_blk.sequence_number != self.sequence_number - 1 if prev_blk else True
        is_next_gap = next_blk.sequence_number != self.sequence_number + 1 if next_blk else True
        if not prev_blk and not next_blk:
            # Is this block a non genesis block? If so, we know nothing about this public key, else pretend the
            # prev_blk exists
            if not is_genesis:
                result[0] = ValidationResult.no_info
            else:
                # We pretend prev_blk exists. This leaves us with next missing, which means partial-next at best.
                result[0] = ValidationResult.partial_next
        elif not prev_blk and next_blk:
            # Is this block a non genesis block?
            if not is_genesis:
                # We are really missing prev_blk. So now partial-prev at best.
                result[0] = ValidationResult.partial_previous
                if is_next_gap:
                    # Both sides are unknown or non-contiguous return a full partial result.
                    result[0] = ValidationResult.partial
            elif is_next_gap:
                # This is a genesis block, so the missing previous is expected. If there is a gap to the next block
                # this reduces the validation result to partial-next
                result[0] = ValidationResult.partial_next
        elif prev_blk and not next_blk:
            # We are missing next_blk, so now partial-next at best.
            result[0] = ValidationResult.partial_next
            if is_prev_gap:
                # Both sides are unknown or non-contiguous return a full partial result.
                result[0] = ValidationResult.partial
        else:
            # both sides have known blocks, see if there are gaps
            if is_prev_gap and is_next_gap:
                result[0] = ValidationResult.partial
            elif is_prev_gap:
                result[0] = ValidationResult.partial_previous
            elif is_next_gap:
                result[0] = ValidationResult.partial_next

        # Step 3: validate that the block is sane, including the validity of the transaction
        # Some basic self tests. It is possible to violate these when constructing a block in code or getting a block
        # from the database. The wire format is such that it impossible to hit many of these for blocks that went over
        # the network.
        tx_validate_res, tx_errors = self.validate_transaction(database)
        if tx_validate_res != ValidationResult.valid:
            result[0] = tx_validate_res
            errors += tx_errors

        if self.sequence_number < GENESIS_SEQ:
            err("Sequence number is prior to genesis")
        if self.link_sequence_number < GENESIS_SEQ and self.link_sequence_number != UNKNOWN_SEQ:
            err("Link sequence number not empty and is prior to genesis")
        if not crypto.is_valid_public_bin(self.public_key):
            err("Public key is not valid")
        else:
            # If the public key is valid, we can use it to check the signature. We want just a yes/no answer here, and
            # we want to keep checking for more errors, so just catch all packing exceptions and err() if any happen.
            try:
                pck = self.pack(signature=False)
            except:
                pck = None
            if pck is None or not crypto.is_valid_signature(
                    crypto.key_from_public_bin(self.public_key), pck, self.signature):
                err("Invalid signature")
        if not crypto.is_valid_public_bin(self.link_public_key):
            err("Linked public key is not valid")
        if self.public_key == self.link_public_key:
            # Blocks to self serve no purpose and are thus invalid.
            err("Self signed block")
        if is_genesis:
            if self.sequence_number == GENESIS_SEQ and self.previous_hash != GENESIS_HASH:
                err("Sequence number implies previous hash should be Genesis ID")
            if self.sequence_number != GENESIS_SEQ and self.previous_hash == GENESIS_HASH:
                err("Sequence number implies previous hash should not be Genesis ID")

        # Step 4: does the database already know about this block? If so it should be equal or else we caught a
        # branch in someones trustchain.
        if blk:
            # Sanity check to see if the database returned the expected block, we want to cover all our bases before
            # crying wolf and making a fraud claim.
            assert blk.public_key == self.public_key and blk.sequence_number == self.sequence_number, \
                "Database returned unexpected block"
            if blk.link_public_key != self.link_public_key:
                err("Link public key does not match known block")
            if blk.link_sequence_number != self.link_sequence_number:
                err("Link sequence number does not match known block")
            if blk.previous_hash != self.previous_hash:
                err("Previous hash does not match known block")
            if blk.signature != self.signature:
                err("Signature does not match known block")
            # if the known block is not equal, and the signatures are valid, we have a double signed PK/seq. Fraud!
            if self.hash != blk.hash and "Invalid signature" not in errors and "Public key is not valid" not in errors:
                err("Double sign fraud")

        # Step 5: does the database have the linked block? If so do the values match up? If the values do not match up
        # someone comitted fraud, but it is impossible to decide who. So we just invalidate the block that is the latter
        # to get validated. We can also detect double counter sign fraud at this point.
        if link:
            # Sanity check to see if the database returned the expected block, we want to cover all our bases before
            # crying wolf and making a fraud claim.
            assert link.public_key == self.link_public_key and \
                   (link.link_sequence_number == self.sequence_number or
                    link.sequence_number == self.link_sequence_number), \
                   "Database returned unexpected block"
            if self.public_key != link.link_public_key:
                err("Public key mismatch on linked block")
            elif self.link_sequence_number != UNKNOWN_SEQ:
                # self counter signs another block (link). If link has a linked block that is not equal to self,
                # then self is fraudulent, since it tries to countersign a block that is already countersigned
                linklinked = database.get_linked(link)
                if linklinked is not None and linklinked.hash != self.hash:
                    err("Double countersign fraud")

        # Step 6: Did we get blocks from the database before or after self? They should be checked for violations too.
        if prev_blk:
            # Sanity check of the block the database gave us.
            assert prev_blk.public_key == self.public_key and prev_blk.sequence_number < self.sequence_number,\
                "Database returned unexpected block"
            if not is_prev_gap and prev_blk.hash != self.previous_hash:
                err("Previous hash is not equal to the hash id of the previous block")
                # Is this fraud? It is certainly an error, but fixing it would require a different signature on the same
                # sequence number which is fraud.

        if next_blk:
            # Sanity check of the block the database gave us.
            assert next_blk.public_key == self.public_key and next_blk.sequence_number > self.sequence_number,\
                "Database returned unexpected block"
            if not is_next_gap and next_blk.previous_hash != self.hash:
                err("Next hash is not equal to the hash id of the block")
                # Again, this might not be fraud, but fixing it can only result in fraud.

        return result[0], errors

    def sign(self, key):
        """
        Signs this block with the given key
        :param key: the key to sign this block with
        """
        crypto = ECCrypto()
        self.signature = crypto.create_signature(key, self.pack(signature=False))
        # If the user is signing his new block, the he also adds a signature for double signing.
        self.double_signature = None

        signature1 = crypto.create_custom_signature(key, self.pack(signature=False), self.public_key)
        signature2 = crypto.create_custom_signature(key, self.pack(signature=True), self.public_key)
        verified1 = crypto.verify_custom_signature(signature1, self.pack(signature=False))
        verified2 = crypto.verify_custom_signature(signature2, self.pack(signature=True))
        print "verified:", verified1
        print "verified:", verified2

        crypto.recover_double_signature(signature1, signature2, self.pack(signature=False), self.pack(signature=True))

    @classmethod
    def create(cls, transaction, database, public_key, link=None, link_pk=None):
        """
        Create an empty next block.
        :param database: the database to use as information source
        :param transaction: the transaction to use in this block
        :param public_key: the public key to use for this block
        :param link: optionally create the block as a linked block to this block
        :param link_pk: the public key of the counterparty in this transaction
        :return: A newly created block
        """
        blk = database.get_latest(public_key)
        ret = cls()
        if link:
            ret.transaction = link.transaction
            ret.link_public_key = link.public_key
            ret.link_sequence_number = link.sequence_number
        else:
            ret.transaction = transaction
            ret.link_public_key = link_pk
            ret.link_sequence_number = UNKNOWN_SEQ

        if blk:
            ret.sequence_number = blk.sequence_number + 1
            ret.previous_hash = blk.hash

        ret.public_key = public_key
        ret.signature = EMPTY_SIG
        return ret

    def pack_db_insert(self):
        """
        Prepare a tuple to use for inserting into the database
        :return: A database insertable tuple
        """
        return (buffer(encode(self.transaction)), buffer(self.public_key), self.sequence_number,
                buffer(self.link_public_key), self.link_sequence_number, buffer(self.previous_hash),
                buffer(self.signature), buffer(self.hash))

    def __iter__(self):
        """
        This override allows one to take the dict(<block>) of a block.
        :return: generator to iterate over all properties of this block
        """
        for key, value in self.__dict__.iteritems():
            if key == 'key' or key == 'serializer':
                continue
            if isinstance(value, basestring) and key != "insert_time":
                yield key, value.encode("hex")
            else:
                yield key, value
        yield "hash", self.hash.encode("hex")

        # "previous_hash_requester": base64.encodestring(self.previous_hash_requester).strip(),
        # "previous_hash_responder": base64.encodestring(self.previous_hash_responder).strip(),
        # "public_key_requester": base64.encodestring(self.public_key_requester).strip(),
        # "signature_requester": base64.encodestring(self.signature_requester).strip(),
        # "public_key_responder": base64.encodestring(self.public_key_responder).strip(),
        # "signature_responder": base64.encodestring(self.signature_responder).strip(),


class ValidationResult(object):
    """
    Contains the various results that the validator can return.
    """

    @staticmethod
    def valid():
        """
        The block does not violate any rules
        """
        pass

    @staticmethod
    def partial():
        """
        The block does not violate any rules, but there are gaps or no blocks on the previous or next block
        """
        pass

    @staticmethod
    def partial_next():
        """
        The block does not violate any rules, but there is a gap or no block on the next block
        """
        pass

    @staticmethod
    def partial_previous():
        """
        The block does not violate any rules, but there is a gap or no block on the previous block
        """
        pass

    @staticmethod
    def no_info():
        """
        There are no blocks (previous or next) to validate against
        """
        pass

    @staticmethod
    def invalid():
        """
        The block violates at least one validation rule
        """
        pass
