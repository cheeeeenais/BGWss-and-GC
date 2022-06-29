from __future__ import annotations

from abc import ABC # abstract base classes
from dataclasses import dataclass
from random import SystemRandom
from typing import Dict, List

from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"my deep dark secret")
# print(token) # b'...'
# print(f.decrypt(token)) # b'my deep dark secret'

# assignments values
COUNT_TTP_get_beaver_triple = 0
COUNT_BGW_create_shares = 0
COUNT_BGW_recover_secret = 0
COUNT_BGW_add = 0
COUNT_BGW_const_mult = 0
COUNT_BGW_mult = 0
MESSAGES_SENT_BGW = 0



@dataclass
class Wire(ABC):
    """Any kind of wire in the circuit."""

    is_output: bool
    """`True` if and only if the value of this wire should be made public after executing the circuit."""


@dataclass
class InputWire(Wire):
    """A wire that corresponds to a client's input."""

    owner_id: int
    """The ID of the client that owns the data for this wire."""


@dataclass
class AddWire(Wire):
    """The output wire of an integer addition gate that computes `A + B`."""

    wire_a_id: int
    """The wire corresponding to input `A`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""

    wire_b_id: int
    """The wire corresponding to input `B`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""


@dataclass
class ConstMultWire(Wire):
    """The output wire of a constant-multiplication gate that computes `c * A`."""

    c: int
    """The constant `c` to multiply with `A`."""

    wire_a_id: int
    """The wire corresponding to input `A`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""


@dataclass
class MultWire(Wire):
    """The output wire of a multiplication gate that computes `A * B`."""

    wire_a_id: int
    """The wire corresponding to input `A`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""

    wire_b_id: int
    """The wire corresponding to input `B`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""


class BGW:
    """Behavior of the BGW protocol."""

    @staticmethod
    def create_shares(rng: SystemRandom, secret: int, share_count: int, mod: int) -> List[int]:
        """Divides the [secret] into [share_count] additive secret shares under modulo [mod] using [rng] as a source of
        randomness."""
        
        # commented because I let also TTP user this function
        # but only when clients call this, is counted
        # see @Client.local_setup()
        # update: not commented anymore
        global COUNT_BGW_create_shares
        COUNT_BGW_create_shares += 1

        shares = []
        # shares = List[int]
        
        # divite the secret into [share_count] - 1 shares
        for _ in range(share_count - 1):
            val = rng.randint(1, 10)
            secret = (secret - val) % mod
            shares.append(val)

        # append the last share
        shares.append(secret)

        return shares

    @staticmethod
    def recover_secret(shares: List[int], mod: int) -> int:
        """Reconstructs the secret that the additive secret [shares] make up under modulo [mod]."""
        
        global COUNT_BGW_recover_secret
        COUNT_BGW_recover_secret += 1

        secret = 0

        for s in shares:
            secret += s
            # secret = (secret + s) % mod

        return secret % mod
        # return secret 

    @staticmethod
    def add(a_share: int, b_share: int, mod: int) -> int:
        """Adds the shares [a_share] and [b_share] together under modulo [mod]."""
        
        global COUNT_BGW_add
        COUNT_BGW_add += 1
            
        # Should we encrypt the shares first?
        # a_enc = f.encrypt(a_share)
        # b_enc = f.encrypt(b_share)

        return (a_share + b_share) % mod
        

    @staticmethod
    def const_mult(c: int, a_share: int, mod: int) -> int:
        """Multiplies the share [a_share] with the constant [c] under modulo [mod]."""
        
        global COUNT_BGW_const_mult
        COUNT_BGW_const_mult += 1

        return (c * a_share) % mod

    @staticmethod
    def mult(is_alice: bool, x_share: int, y_share: int, z_share: int, a_prime: int, b_prime: int, mod: int) -> int:
        """Performs the masked multiplication corresponding to `A * B` using the formula from the slides, under modulo
        [mod]. The constant term is added only if [is_alice] is `True`."""

        global COUNT_BGW_mult
        COUNT_BGW_mult += 1

        if is_alice:
            return (a_prime * b_prime + a_prime * y_share + b_prime * x_share + z_share) % mod
        else:
            return (a_prime * y_share + b_prime * x_share + z_share) % mod


    # ######################## LAST ########################
    @staticmethod
    def run_circuit(clients: List[Client]) -> Dict[int, int]:
        """Makes the [clients] interactively compute their circuit by synchronously invoking their methods, and returns
        all outputs of the circuit."""

        client_pos = {}
        

        for client in clients:
            client.set_clients(clients)
            client.local_setup() #  already in the client.run_circuit_until_mult

        for client in clients:
            client.interactive_setup() # already in the client.run_circuit_until_mult
            
            client_pos[client.client_id] = 0


        while 1:
            for client in clients:
                # if client_pos[client.client_id] != None:
                client_pos[client.client_id] = client.run_circuit_until_mult(client_pos[client.client_id]) 

            # # if all clients done
            if all(client_pos[client.client_id] == None for client in clients):
                break

            

        return clients[0].get_outputs()

            # for client in clients:

            #     # do the final computation
            #     to_be_continued = client.run_circuit_until_mult(to_be_continued) 



class TTP:
    """A trusted third party that can be trusted to generate Beaver triples."""

    def __init__(self, client_count: int, mod: int, rng: SystemRandom):
        """Initializes this [TTP], given the number of clients [client_count] participating in the protocol, the modulo
        [mod] to perform secret sharing under, and a source of randomness [rng]."""
        

        self.mod = mod
        self.rng = rng
        self.client_count = client_count

        self.beaver_triples = {}

    # def get_beaver_triple(self, wire_id: int, client_id: int) -> [int, int, int]:
    def get_beaver_triple(self, wire_id: int, client_id: int) -> List[int]:
        """Returns shares of the Beaver triple for multiplication gate [wire_id] for [client_id]. Make sure that clients
        requesting shares for the same [wire_id] actually get shares of the same Beaver triple."""
        
        global COUNT_TTP_get_beaver_triple
        COUNT_TTP_get_beaver_triple += 1

        if wire_id not in self.beaver_triples:
            X = self.rng.randint(1, 10)
            Y = self.rng.randint(1, 10)
            Z = (X * Y) % self.mod # not sure about the mod

            self.beaver_triples[wire_id] = [[] for _ in range(self.client_count)]

            X_shares = BGW.create_shares(self.rng, X, self.client_count, self.mod)
            Y_shares = BGW.create_shares(self.rng, Y, self.client_count, self.mod)
            Z_shares = BGW.create_shares(self.rng, Z, self.client_count, self.mod)

            for client in range(self.client_count):
                
                self.beaver_triples[wire_id][client].append(X_shares[client])
                self.beaver_triples[wire_id][client].append(Y_shares[client])
                self.beaver_triples[wire_id][client].append(Z_shares[client])

            # # array of lists: [client_index][x,y,z]
            # shares = [[] for _ in range(self.client_count)]

            # # compute shares
            # for i in range(self.client_count - 1):
            #     x, y, z = self.rng.randint(1, 10), self.rng.randint(1, 10), self.rng.randint(1, 10)
            #     X = (X - x) % self.mod
            #     Y = (Y - y) % self.mod
            #     Z = (Z - z) % self.mod
            #     shares[i].append(x)
            #     shares[i].append(y)
            #     shares[i].append(z)

            # shares[self.client_count - 1].append(X)
            # shares[self.client_count - 1].append(Y)
            # shares[self.client_count - 1].append(Z)

            # # save shares in map
            # self.beaver_triples[wire_id] = shares

        # hypotize that client_ids are in order (ie alice = 0, bob = 1)
        return self.beaver_triples[wire_id][client_id]
        


class Client:
    """A client in the BGW protocol."""

    # Client(0, ttp, circuit, {0: 9}, mod, rng),
    # Client(1, ttp, circuit, {1: 5}, mod, rng),
    # Client(2, ttp, circuit, {2: 3}, mod, rng)
    def __init__(self, client_id: int, ttp: TTP, circuit: List[Wire], inputs: Dict[int, int], mod: int,
                 rng: SystemRandom):
        """Constructs a new [Client], but does not do any significant computation yet. Here, [client_id] uniquely
        identifies this client, [ttp] is the TTP that will provide the client with shares of Beaver triples, [circuit]
        is the circuit that will be executed, [inputs] is a mapping from wire indices to this client's private input
        values, [mod] is the modulo under which the circuit is computed, and [rng] is the source of randomness used
        whenever possible."""
        

        self.client_id = client_id
        self.ttp = ttp
        self.circuit = circuit
        self.inputs = inputs
        self.mod = mod
        self.rng = rng

        # self.clients_shares = {} # maps clients' (usually Bob's) id(s) -> my share for his(their) value(s) (eg, I'm Alice: Bob -> [B]_A)
        # self.beaver_triple = {} # maps wire_id -> my share for X, Y, Z

    def set_clients(self, clients: List[Client]):
        """Gives this client knowledge of the [Client]s that participate in the protocol."""
        

        self.clients = clients

    def get_input_share(self, wire_id: int, requester_id: int) -> int:
        """Returns the share of this client's input at wire [wire_id] that they created for client [requester_id]. This
        client should validate that this request is sensible, but may assume that the requester is
        honest-but-curious."""
        

        return self.my_input_shares[wire_id][requester_id]
        # return self.shares[wire_id][requester_id]

    # def get_masked_shares(self, wire_id: int) -> [int, int]:
    def get_masked_shares(self, wire_id: int) -> List[int]:
        """Returns the masked shares `A - X` and `B - Y` that this client created for the multiplication at wire
        [wire_id]."""

        wire = self.circuit[wire_id]

        A = self.shares[wire.wire_a_id]
        B = self.shares[wire.wire_b_id]
        X = self.triple[wire_id][0]
        Y = self.triple[wire_id][1]

        masked_shares = []
        # self.masked_shares = []
        # self.masked_shares.append(A - X)
        # masked_shares.append(A - X)
        masked_shares.append((A - X) % self.mod)
        # masked_shares.append(B - Y)
        masked_shares.append((B - Y) % self.mod)
        # self.masked_shares.append(B - Y)

        return masked_shares
        # return self.masked_shares

    def get_output_share(self, wire_id: int) -> int:
        """Returns the share that this client calculated for the wire [wire_id], to be used to reconstruct the value of
        this wire. This client should validate that this request is sensible, but may assume that the requester is
        honest-but-curious."""
        

        wire = self.circuit[wire_id]

        if type(wire) == AddWire:
            return BGW.add(self.shares[wire.wire_a_id], self.shares[wire.wire_b_id], self.mod)
        elif type(wire) == ConstMultWire:
            return BGW.const_mult(wire.c, self.shares[wire.wire_a_id], self.mod)
        elif type(wire) == MultWire:
            return BGW.mult(self.client_id == 0, self.triple[wire_id][0], self.triple[wire_id][1], self.triple[wire_id][2], self.a_b_prime[wire_id][0], self.a_b_prime[wire_id][1], self.mod)
        elif type(wire) == InputWire:
            return self.shares[wire_id]



    def local_setup(self):
        """Performs the local part of the setup, which consists of creating shares for this client's inputs."""
        
        self.my_input_shares = {}
        """Share my input to [len(clients)] clients: wire_id: int -> shares: List[int]"""

        for wire_index, input in self.inputs.items():
            self.my_input_shares[wire_index] = BGW.create_shares(self.rng, input, len(self.clients), self.mod)
            # global COUNT_BGW_create_shares
            # COUNT_BGW_create_shares += 1
            

    def interactive_setup(self):
        """Performs the interactive part of the setup, which consist of retrieving shares of Beaver triples from the
        TTP and fetching the shares that other clients have created of their inputs for this client."""
        

        self.shares = {}
        """Contain all my shares for each wire"""

        self.triple = {}
        """Contain all the Beaver stiple shares for each MultWire"""

        self.masked_shares = {} # not used in this function
        """Contain all the masked shares [(A-X), (B-Y)] for each MultWire"""

        self.a_b_prime = {} # not used in this function
        """Contain a_prime and b_prime for each MultWire"""
        

        for wire_index, wire in enumerate(self.circuit):
            if type(wire) ==  InputWire:
                if wire.owner_id != self.client_id:
                    global MESSAGES_SENT_BGW
                    MESSAGES_SENT_BGW += 1

                self.shares[wire_index] = self.clients[wire.owner_id].get_input_share(wire_index, self.client_id)
            elif type(wire) ==  MultWire:
                # global MESSAGES_SENT_BGW
                MESSAGES_SENT_BGW += 1

                # self.shares_braver_triple[wire_index] = self.ttp.get_beaver_triple(wire_index, self.client_id)
                self.triple[wire_index] = self.ttp.get_beaver_triple(wire_index, self.client_id)
        



    def run_circuit_until_mult(self, start_at_wire_id: int) -> int | None:
        """Runs the circuit starting at wire [start_at_wire_id] until it encounters a multiplication gate. If a
        multiplication gate is encountered, this client performs some local computation, and then returns the id of the
        wire it stopped at. This client may assume that the next time this method is invoked, it continues at the
        multiplication it left off at by performing the interactive part of the multiplication. After that, this client
        continues to run the circuit until it encounters another multiplication gate. If this client is done with the
        circuit, this function returns `None`."""

        # Dict[wire_id: int, all_output_shares: List[int]] -> needed to use get_output()
        # self.output_shares = {}

        for wire_index in range(start_at_wire_id, len(self.circuit)):

            # we don't want InputWire
            if type(self.circuit[wire_index]) != InputWire:

                # if doesn't require interaction (AddWire, ConstMultWire)
                if type(self.circuit[wire_index]) != MultWire:
                    # wire = self.circuit[wire_index]

                    # save the "output share" in my shares
                    self.shares[wire_index] = self.get_output_share(wire_index)

                # GateWire moment
                else:
                    # first time encoutering MultWire -> setup
                    if wire_index not in self.masked_shares:
                        # some local computation

                        # self.triple = self.ttp.get_beaver_triple(wire_index, self.client_id)
                        self.masked_shares[wire_index] = self.get_masked_shares(wire_index)

                        # still need to exchange the masked shares

                        return wire_index
                    

                    # second time encountering MultWire -> execute
                    else:                        
                        # share the masked shares with other clients (receive other clients' masked shares)
                        masked_a = []
                        masked_b = []
                        for client_ in self.clients:
                            masked_a.append(client_.get_masked_shares(wire_index)[0])
                            masked_b.append(client_.get_masked_shares(wire_index)[1])

                        # recover A' and B'
                        self.a_b_prime[wire_index] = []
                        self.a_b_prime[wire_index].append(BGW.recover_secret(masked_a, self.mod))
                        self.a_b_prime[wire_index].append(BGW.recover_secret(masked_b, self.mod))

                        # get share of the output of the GateWire
                        self.shares[wire_index] = self.get_output_share(wire_index)

                # if self.circuit[wire_index].is_output:
                    # return None
        
        return None

        # print(self.get_outputs())

        # self.output_shares[wire_index] = self.get_output_share(wire_index)
            # self.output_shares[wire_index] = []
            # for client in self.clients:
            #     self.output_shares[wire_index].append(client.get_output_share(wire_index))

        return wire_index

        

        """
        wire = self.circuit[start_at_wire_id]

        if type(wire) == MultWire:
            self.interactive_setup()

            start_at_wire_id += 1

        else:
            if type(wire) == InputWire and self.client_id == wire.owner_id:
                self.local_setup()

            elif type(wire) == AddWire:
                # these are already done in interactive_setup()
                # share1 = self.get_input_share(wire.wire_a_id, self.client_id)
                # share2 = self.get_input_share(wire.wire_b_id, self.client_id)

                self.output_shares[start_at_wire_id] = []
                # self.output_shares[start_at_wire_id] = self.get_output_share(start_at_wire_id)
                # self.output_shares[start_at_wire_id].append(self.get_output_share(start_at_wire_id))
                for client in range(self.clients):
                    self.output_shares[start_at_wire_id].append(self.clients[client].get_output_share(start_at_wire_id))

                self.get_outputs()


        while start_at_wire_id < len(self.circuit) and type(wire) != MultWire:
            start_at_wire_id += 1

        if start_at_wire_id == len(self.circuit):
            return None
        else:
            self.local_setup()
            return start_at_wire_id
        
        # else:
        #     while type(self.circuit[start_at_wire_id]) != MultWire:
        #         start_at_wire_id += 1

        #     self.local_setup()

        #     return start_at_wire_id


        # # (probably) useless check
        # if start_at_wire_id < len(self.circuit) and start_at_wire_id >= 0:

        #     # wire comparisons
        #     current_wire = self.circuit[start_at_wire_id]
            
        #     while type(current_wire) != MultWire:

        #         if type(current_wire) == InputWire:
        #             start_at_wire_id += 1 
        #             current_wire = self.circuit[start_at_wire_id]

        #         elif type(current_wire) == AddWire:
        #             BGW.add(self.shares, self.others[0], self.mod)

        #         elif type(current_wire) == ConstMultWire:
        #             BGW.const_mult(current_wire.c, current_wire.wire_a_id) # wrong
        """



    def get_outputs(self) -> Dict[int, int]:
        """Returns a dictionary from wire IDs to the reconstructed outputs at those wires, corresponding to all outputs
        of the circuit."""
        outputs = {}

        for wire_index, wire in enumerate(self.circuit):
            # output_shares = []
            # output_shares.append(self.get_output_share(wire_index))

            # for client in self.clients:
            #     output_shares.append(client.get_output_share(wire_index))

            # if type(wire) != InputWire:
            if wire.is_output:

                # D = [D]_A + [D]_B + [D]_C
                output_shares = []

                for client in self.clients:
                    # output_shares.append(client.get_output_share(wire_index))
                    output_shares.append(client.shares[wire_index])
                    
                    if client != self:
                        global MESSAGES_SENT_BGW
                        MESSAGES_SENT_BGW += 1 * len(self.clients) # this is because I just let one user know the final result
                                                               # instead of letting all three know (so * "3" to let all 3 know)

                # basically just add the shares
                outputs[wire_index] = BGW.recover_secret(output_shares, self.mod) 


        # return self.outputs
        return outputs



def main():
    circuits = {
        # basic
        # 0 - |
        #     + -> |
        # 1 - |    |
        #          |
        #          * -> output
        #          |
        # 2 - |    |
        #    6* -> |  


        # inputs: {0: 9}, {1: 5}, {2: 3}
        "basic": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=1),  # 1
            InputWire(is_output=False, owner_id=2),  # 2
            AddWire(is_output=False, wire_a_id=0, wire_b_id=1),  # 3
            # AddWire(is_output=True, wire_a_id=0, wire_b_id=1),  # test
            ConstMultWire(is_output=False, c=6, wire_a_id=2),  # 4
            # AddWire(is_output=True, wire_a_id=3, wire_b_id=4),  # test
            # ConstMultWire(is_output=True, c=5, wire_a_id=4),  # test
            MultWire(is_output=True, wire_a_id=3, wire_b_id=4),  # 5
            # MultWire(is_output=True, wire_a_id=0, wire_b_id=1),  # test
        ],
        "deep": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=1),  # 1
            InputWire(is_output=False, owner_id=2),  # 2
            InputWire(is_output=False, owner_id=2),  # 3
            AddWire(is_output=False, wire_a_id=0, wire_b_id=1),  # 4
            MultWire(is_output=False, wire_a_id=4, wire_b_id=2),  # 5
            AddWire(is_output=False, wire_a_id=1, wire_b_id=5),  # 6
            ConstMultWire(is_output=False, c=4, wire_a_id=6),  # 7
            AddWire(is_output=False, wire_a_id=2, wire_b_id=7),  # 8
            AddWire(is_output=False, wire_a_id=7, wire_b_id=8),  # 9
            MultWire(is_output=False, wire_a_id=4, wire_b_id=9),  # 10
            MultWire(is_output=True, wire_a_id=3, wire_b_id=10),  # 11
        ],
        "wide": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=0),  # 1
            InputWire(is_output=False, owner_id=0),  # 2
            InputWire(is_output=False, owner_id=0),  # 3
            InputWire(is_output=False, owner_id=1),  # 4
            InputWire(is_output=False, owner_id=1),  # 5
            InputWire(is_output=False, owner_id=1),  # 6
            InputWire(is_output=False, owner_id=1),  # 7
            InputWire(is_output=False, owner_id=2),  # 8
            InputWire(is_output=False, owner_id=2),  # 9
            InputWire(is_output=False, owner_id=2),  # 10
            InputWire(is_output=False, owner_id=2),  # 11
            AddWire(is_output=False, wire_a_id=0, wire_b_id=6),  # 12
            AddWire(is_output=False, wire_a_id=1, wire_b_id=7),  # 13
            AddWire(is_output=False, wire_a_id=2, wire_b_id=8),  # 14
            AddWire(is_output=False, wire_a_id=3, wire_b_id=9),  # 15
            AddWire(is_output=False, wire_a_id=4, wire_b_id=10),  # 16
            AddWire(is_output=False, wire_a_id=5, wire_b_id=11),  # 17
            MultWire(is_output=True, wire_a_id=12, wire_b_id=15),  # 18
            MultWire(is_output=True, wire_a_id=13, wire_b_id=16),  # 19
            MultWire(is_output=True, wire_a_id=14, wire_b_id=17),  # 20
        ],
        "adder": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=1),  # 1
            InputWire(is_output=False, owner_id=2),  # 2
            AddWire(is_output=False, wire_a_id=0, wire_b_id=1),  # 3
            AddWire(is_output=True, wire_a_id=3, wire_b_id=2),  # 4
        ],
        "xors": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=0),  # 1
            InputWire(is_output=False, owner_id=1),  # 2
            InputWire(is_output=False, owner_id=1),  # 3
            InputWire(is_output=False, owner_id=2),  # 4
            InputWire(is_output=False, owner_id=2),  # 5
            # "Gate 6"
            AddWire(is_output=False, wire_a_id=0, wire_b_id=3),  # 6
            MultWire(is_output=False, wire_a_id=0, wire_b_id=3),  # 7
            ConstMultWire(is_output=False, c=-2, wire_a_id=7),  # 8
            AddWire(is_output=True, wire_a_id=6, wire_b_id=8),  # 9
            # "Gate 7"
            AddWire(is_output=False, wire_a_id=1, wire_b_id=4),  # 10
            MultWire(is_output=False, wire_a_id=1, wire_b_id=4),  # 11
            ConstMultWire(is_output=False, c=-2, wire_a_id=11),  # 12
            AddWire(is_output=True, wire_a_id=10, wire_b_id=12),  # 13
            # "Gate 8"
            AddWire(is_output=False, wire_a_id=2, wire_b_id=5),  # 14
            MultWire(is_output=False, wire_a_id=2, wire_b_id=5),  # 15
            ConstMultWire(is_output=False, c=-2, wire_a_id=15),  # 16
            AddWire(is_output=True, wire_a_id=14, wire_b_id=16),  # 17
            # "Gate 9"
            AddWire(is_output=False, wire_a_id=3, wire_b_id=9),  # 18
            MultWire(is_output=False, wire_a_id=3, wire_b_id=9),  # 19
            ConstMultWire(is_output=False, c=-2, wire_a_id=19),  # 20
            AddWire(is_output=True, wire_a_id=18, wire_b_id=20),  # 21
            # "Gate 10"
            AddWire(is_output=False, wire_a_id=4, wire_b_id=13),  # 22
            MultWire(is_output=False, wire_a_id=4, wire_b_id=13),  # 23
            ConstMultWire(is_output=False, c=-2, wire_a_id=23),  # 24
            AddWire(is_output=True, wire_a_id=22, wire_b_id=24),  # 25
            # "Gate 11"
            AddWire(is_output=False, wire_a_id=5, wire_b_id=17),  # 26
            MultWire(is_output=False, wire_a_id=5, wire_b_id=17),  # 27
            ConstMultWire(is_output=False, c=-2, wire_a_id=27),  # 28
            AddWire(is_output=True, wire_a_id=26, wire_b_id=28),  # 29
            # "Gate 12"
            AddWire(is_output=False, wire_a_id=9, wire_b_id=21),  # 30
            MultWire(is_output=False, wire_a_id=9, wire_b_id=21),  # 31
            ConstMultWire(is_output=False, c=-2, wire_a_id=31),  # 32
            AddWire(is_output=True, wire_a_id=30, wire_b_id=32),  # 33
            # "Gate 13"
            AddWire(is_output=False, wire_a_id=13, wire_b_id=25),  # 34
            MultWire(is_output=False, wire_a_id=13, wire_b_id=25),  # 35
            ConstMultWire(is_output=False, c=-2, wire_a_id=35),  # 36
            AddWire(is_output=True, wire_a_id=34, wire_b_id=36),  # 37
            # "Gate 14"
            AddWire(is_output=False, wire_a_id=29, wire_b_id=33),  # 38
            MultWire(is_output=False, wire_a_id=29, wire_b_id=33),  # 39
            ConstMultWire(is_output=False, c=-2, wire_a_id=39),  # 40
            AddWire(is_output=True, wire_a_id=38, wire_b_id=40),  # 41
            # "Gate 15"
            AddWire(is_output=False, wire_a_id=41, wire_b_id=37),  # 42
            MultWire(is_output=False, wire_a_id=41, wire_b_id=37),  # 43
            ConstMultWire(is_output=False, c=-2, wire_a_id=43),  # 44
            AddWire(is_output=True, wire_a_id=42, wire_b_id=44),  # 45
        ]
    }

    # circuit = circuits["deep"] 
    circuit = circuits["wide"] 
    # circuit = circuits["adder"] 
    # circuit = circuits["xors"] 
    mod = 1024
    rng = SystemRandom(0)

    ttp = TTP(3, mod, rng)
    clients = [
        # Client(0, ttp, circuit, {0: 9}, mod, rng), # basic, deep, adder
        # Client(1, ttp, circuit, {1: 5}, mod, rng), # basic, deep, adder
        # Client(2, ttp, circuit, {2: 3}, mod, rng) # basic, adder
        # Client(2, ttp, circuit, {2: 3, 3: 4}, mod, rng) # deep
        Client(0, ttp, circuit, {0: 3, 1: 2, 2: 1, 3: 7}, mod, rng), # wide
        Client(1, ttp, circuit, {4: 3, 5: 4, 6: 4, 7: 9}, mod, rng), # wide
        Client(2, ttp, circuit, {8: 9, 9: 2, 10: 10, 11: 7}, mod, rng) # wide
        # Client(0, ttp, circuit, {0: 1, 1: 1}, mod, rng), # xors
        # Client(1, ttp, circuit, {2: 1, 3: 0}, mod, rng), # xors
        # Client(2, ttp, circuit, {4: 1, 5: 1}, mod, rng) # xors
    ]

    print(BGW.run_circuit(clients))


    print("COUNT_TTP_get_beaver_triple:", COUNT_TTP_get_beaver_triple)
    print("COUNT_BGW_create_shares:", COUNT_BGW_create_shares)
    print("COUNT_BGW_recover_secret:", COUNT_BGW_recover_secret)
    print("COUNT_BGW_add:", COUNT_BGW_add)
    print("COUNT_BGW_const_mult:", COUNT_BGW_const_mult)
    print("COUNT_BGW_mult:", COUNT_BGW_mult)
    print("MESSAGES_SENT_BGW:", MESSAGES_SENT_BGW)


    # ######################## TESTING ########################
    # triples = []
    # for i in range(3):
    #     triples.append(ttp.get_beaver_triple(0, i))

    # rec1 = []
    # rec2 = []
    # rec3 = []
    # for i in range(3):
    #     rec1.append(triples[i][0])
    #     rec2.append(triples[i][1])
    #     rec3.append(triples[i][2])

    # print(BGW.recover_secret(rec1, mod))
    # print(BGW.recover_secret(rec2, mod))
    # print(BGW.recover_secret(rec3, mod))
    # ######################## TESTING ########################

if __name__ == "__main__":
    
    main()
