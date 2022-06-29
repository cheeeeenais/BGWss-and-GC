from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import Callable, Dict, List

from cryptography.fernet import Fernet, InvalidToken

# key = Fernet.generate_key()
# f = Fernet(key)
# token = f.encrypt(b"my deep dark secret") # type(token) = bytes
# print(token) # b'...'
# print(f.decrypt(token)) # b'my deep dark secret'

COUNT_AES_Encrypt = 0
COUNT_AES_Decrypt = 0
COUNT_OT = 0
MESSAGES_SENT_GC = 0

@dataclass
class Wire(ABC):
    """Any kind of wire in the circuit."""

    is_output: bool
    """`True` if and only if the value of this wire should be made public after executing the circuit."""


@dataclass
class InputWire(Wire):
    """A wire that corresponds to a client's input."""

    alice_is_owner: bool
    """`True` if and only if Alice (the garbler) is the owner of this input data."""


@dataclass
class GateWire(Wire):
    """The output wire of a gate that operates on inputs `X` and `Y` and outputs a value according to [gate]."""

    input_x_id: int
    """The wire corresponding to input `X`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""

    input_y_id: int
    """The wire corresponding to input `Y`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""

    gate: Callable[[bool, bool], bool]
    """Determines the output of this gate given the inputs."""


@dataclass
class GarbledGateWire(Wire):
    """The garbled output wire of a gate that operates on inputs `X` and `Y` and outputs a value as encoded by the
    garbled [keys]."""

    input_x_id: int
    """The wire corresponding to input `X`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""

    input_y_id: int
    """The wire corresponding to input `Y`, as identified by that wire's index in the list of wires (i.e. circuit) that 
    this wire is part of."""

    keys: List[bytes]
    """The list of keys for the outputs of this wire."""


class Alice:
    """Alice, the client who garbles the circuit."""

    def __init__(self, circuit: List[Wire], inputs: Dict[int, bool]):
        """Initializes Alice with knowledge of the [circuit] and her own private [inputs]."""
        

        self.circuit = circuit
        self.inputs = inputs

    def generate_wire_keys(self):
        """Generates a pair of keys for each wire in the circuit, one representing `True` and the other representing
        `False`."""
        

        self.keys = {}

        for wire_index in range(len(self.circuit)):
            key_0 = Fernet.generate_key()
            key_1 = Fernet.generate_key()

            self.keys[wire_index] = [key_0, key_1]



    def generate_garbled_circuit(self):
        """Generates the garbled circuit. In a garbled circuit, the [InputWire]s are the same, but each [GateWire] is
        replaced by a [GarbledGateWire]."""
        

        # enc_output = 0

        # for wire in self.circuit:
        #     if wire == GateWire:
        #         enc_output = self.keys[wire][0].encrypt()
        #         enc_output.

        # wire_index -> garbled table (list of encrypted Zs)
        self.garbled_table = {}

        for wire_index, wire in enumerate(self.circuit):
            if type(wire) == GateWire:
                # GateWire(is_output=False, input_x_id=0, input_y_id=1, gate=gates["or"]),  # 4

                self.garbled_table[wire_index] = []

                # take the input keys
                input_keys_x = []
                input_keys_y = []
                # input_keys_x.append(Fernet(self.keys[wire_x][0]))
                # input_keys_x.append(Fernet(self.keys[wire_x][1]))
                # input_keys_y.append(Fernet(self.keys[wire_y][0]))
                # input_keys_y.append(Fernet(self.keys[wire_y][1]))
                input_keys_x.append(self.keys[wire.input_x_id][0])
                input_keys_x.append(self.keys[wire.input_x_id][1])
                input_keys_y.append(self.keys[wire.input_y_id][0])
                input_keys_y.append(self.keys[wire.input_y_id][1])

                # for i in range(2):
                for i in range(1, -1, -1):
                    # for j in range(2):
                    for j in range(1, -1, -1):
                        # garbled_table.append(input_keys_x[i].encrypt(input_keys_y[j].encrypt(wire.gate(i, j).to_bytes(1, 'big'))))
                        # wire_output_bytes = wire.gate(i, j).to_bytes(1, 'big')
                        output_key = self.keys[wire_index][wire.gate(i, j)] 
                        # self.garbled_table[wire_index] = Fernet(input_keys_x[i]).encrypt(Fernet(input_keys_y[j]).encrypt(wire_output_bytes))
                        self.garbled_table[wire_index].append(Fernet(input_keys_x[i]).encrypt(Fernet(input_keys_y[j]).encrypt(output_key)))
                        global COUNT_AES_Encrypt
                        COUNT_AES_Encrypt += 2

                self.circuit[wire_index] = GarbledGateWire(wire.is_output, wire.input_x_id, wire.input_y_id, self.garbled_table[wire_index])


    def get_garbled_circuit(self, wire_id: int) -> List[bytes]:
        """Return the garbled table for the [wire_id]"""
        global MESSAGES_SENT_GC 
        MESSAGES_SENT_GC += 1

        # return self.garbled_table[wire_id] 
        return self.circuit[wire_id]

    def get_alice_input_key(self, wire_id: int) -> bytes:
        """Returns the key corresponding to Alice's input at wire [wire_id]."""
        global MESSAGES_SENT_GC 
        MESSAGES_SENT_GC += 1

        if self.inputs[wire_id] == True:
            return self.keys[wire_id][1] 
        else: 
            return self.keys[wire_id][0]


    def get_bob_input_key(self, wire_id: int, bobs_private_value: bool) -> bytes:
        """Runs oblivious transfer to allow Bob to retrieve the key for wire [wire_id] for Bob's private value
        [bobs_private_value]. For simplicity, you may assume that Alice is super duper honest and will definitely not
        remember the fact that Bob sent his private value to her. So you can just return the correct key here directly
        without any cryptography going on."""
        global COUNT_OT
        COUNT_OT += 1
        global MESSAGES_SENT_GC 
        MESSAGES_SENT_GC += 1

        # not sure
        return self.keys[wire_id][bobs_private_value]

        # if self.circuit[wire_id].alice_is_owner == False:
        #     return self.keys[wire_id][bobs_private_value]

    def get_output(self, wire_id: int, key: bytes) -> bool:
        """Returns the output bit corresponding to wire [wire_id] given that Bob found [key] for this wire. Alice should
         validate that this request is sensible, but may assume that Bob is honest-but-curious."""
        global MESSAGES_SENT_GC
        MESSAGES_SENT_GC += 1

        if self.keys[wire_id][0] == key:
            return False
        elif self.keys[wire_id][1] == key:
            return True
        else:
            print("Error Error please evacuate")


class Bob:
    """Bob, the client who evaluates the garbled circuit."""

    def __init__(self, alice: Alice, inputs: Dict[int, bool]):
        """Initializes Bob with knowledge of [Alice] and his own private [inputs]."""
        

        self.alice = alice
        self.inputs = inputs

    def get_setup_info(self):
        """Retrieves the following information from Alice: the garbled circuit, Alice's input keys, and Bob's input
        keys."""
        

        # self.alice.generate_garbled_circuit()
        # self.garbled_circuit = self.alice.circuit
        self.garbled_circuit = {}

        # print("#################")
        # print(self.garbled_circuit)
        # print(self.alice.circuit)
        # print("#################")


        # self.alice_keys = {}
        # self.bob_keys = {}
        self.input_keys = {}

        # for each wire (not sure)
        for wire_index, wire in enumerate(self.alice.circuit):
            if type(wire) == GarbledGateWire:
                self.garbled_circuit[wire_index] = self.alice.get_garbled_circuit(wire_index)

            # if InputWire -> take the keys
            if type(wire) == InputWire:
                if wire.alice_is_owner:
                    # self.alice_keys[wire_index] = self.alice.inputs[wire_index]
                    # self.alice_keys[wire_index] = self.alice.get_alice_input_key(wire_index)
                    self.input_keys[wire_index] = self.alice.get_alice_input_key(wire_index)
                    
                else:
                    # self.bob_keys[wire_index] = self.inputs[wire_index]
                    # self.bob_keys[wire_index] = self.alice.keys[wire_index][self.inputs[wire_index]]
                    # self.bob_keys[wire_index] = self.alice.get_bob_input_key(wire_index, self.inputs[wire_index])
                    self.input_keys[wire_index] = self.alice.get_bob_input_key(wire_index, self.inputs[wire_index])
                

                

                

            # if GateWire -> take the garbled circuits
            # elif type(self.alice.circuit[wire_index]) == GarbledGateWire:
            #     self.alice.circuit[wire_index] = self.alice.get_garbled_circuit(wire_index)


        # self.alice_keys = self.alice.keys

        # self.keys = {}

        # for wire_index in range(len(self.garbled_circuit)):
        #     key_false = Fernet.generate_key()
        #     key_true = Fernet.generate_key()

        #     # notice -> index: Wire (not int)
        #     self.keys[wire_index] = [key_false, key_true]

    def evaluate(self):
        """Evaluates the garbled circuit retrieved from Alice. At the end of this method, Bob knows exactly which output
        keys belong to which wire, but has not learnt more about whether they correspond to `True` or `False`."""
        

        self.output_keys = {}

        # for wire_index, wire in enumerate(self.garbled_circuit):
        for wire_index, wire in self.garbled_circuit.items():

            # if type(self.garbled_circuit[wire_index]) == InputWire:
            #     if self.garbled_circuit[wire_index].alice_is_owner == True:
            #         self.alice_keys[wire_index] = self.alice.get_alice_input_key(wire_index)
            #     else:
            #         self.bob_keys[wire_index] = self.alice.get_bob_input_key(wire_index, self.inputs[wire_index])

            if type(wire) == GarbledGateWire:

                # self.output_keys[wire_index] = []

                # for each key -> decrypt
                # for index, key in enumerate(wire.keys):
                for z_key in wire.keys:
                    # print(type(key))

                    # 1st attempt
                    # self.output_keys[wire_index].append(Fernet(self.alice_keys[wire_index]).decrypt(Fernet(self.bob_keys[wire_index]).decrypt(z_key)))
                    
                    # 2nd attempt
                    # decr_y = Fernet(self.bob_keys[wire.input_y_id]).decrypt(z_key)
                    # decr_x = Fernet(self.alice_keys[wire.input_x_id]).decrypt(decr_y)
                    # self.output_keys[wire_index].append(decr_x)
                    
                    global COUNT_AES_Decrypt
                    COUNT_AES_Decrypt += 2

                    # 3rd attempt
                    try:
                        decr_x = Fernet(self.input_keys[wire.input_x_id]).decrypt(z_key)
                        decr_y = Fernet(self.input_keys[wire.input_y_id]).decrypt(decr_x)
                        self.output_keys[wire_index] = decr_y 
                        # print("Found the Z!", decr_y)
                        self.input_keys[wire_index] = decr_y
                        break
                    except (InvalidToken, ValueError):
                        pass


    def retrieve_outputs(self) -> Dict[int, bool]:
        """Determines the semantic meaning of the keys that Bob obtained in [evaluate] for the output wires by
        interacting with Alice."""

        self.final_outputs = {}

        # for wire_index, wire in enumerate(self.garbled_circuit):
        for wire_index, wire in self.garbled_circuit.items():
            # if type(self.garbled_circuit[wire_index]) != InputWire:
            if wire.is_output:
                self.final_outputs[wire_index] = self.alice.get_output(wire_index, self.output_keys[wire_index])

        return self.final_outputs


def run_garbled_circuit(alice: Alice, bob: Bob) -> Dict[int, bool]:
    """Evaluates the garbled circuit through Alice and Bob and returns the outputs."""
    

    # outputs = {}

    # print("Started, that's cool")

    # print("Alice starts generating keys...")
    alice.generate_wire_keys()
    # print("Keys generated!")
    # print(alice.keys)

    # print("Alice starts generating the garbled circuits...")
    alice.generate_garbled_circuit()
    # print("Garbled circuits generated!")

    # print("Bob retrieving the garbled circuits, Alice's input keys and Bob's input keys...")
    bob.get_setup_info()
    # print("He got them!")
    # print("Garbled circuit:", bob.garbled_circuit)
    # print("Alice keys:", bob.alice_keys)
    # print("Bob keys:", bob.bob_keys)

    # for wire_index in range(len(bob.garbled_circuit)):
    #     if type(wire_index) == InputWire:
    #         bob.alice.get_alice_input_key(wire_index)
    
    # print("Bob is evaluating...")
    bob.evaluate()
    # print("Bob has learnt the output keys! He still doesn't know which output they represent tho..")
    # print(bob.output_keys)

    # alice.get_bob_input_key()
    # alice.get_output()
    # outputs = bob.retrieve_outputs()

    # print("Bob got the outputs!")
    return bob.retrieve_outputs()



def main():
    gates = {
        "and": lambda x, y: x and y,
        "or": lambda x, y: x or y,
        "xor": lambda x, y: x != y,
        "if": lambda x, y: x <= y,
        "iff": lambda x, y: x == y,
        "not-x": lambda x, y: not x,
        "not-y": lambda x, y: not y,
    }

    circuits = {
        "basic": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=False),  # 2
            InputWire(is_output=False, alice_is_owner=False),  # 3
            GateWire(is_output=False, input_x_id=0, input_y_id=1, gate=gates["or"]),  # 4
            GateWire(is_output=False, input_x_id=2, input_y_id=3, gate=gates["or"]),  # 5
            GateWire(is_output=True, input_x_id=4, input_y_id=5, gate=gates["and"]),  # 6
        ],
        "deep": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=False),  # 2
            InputWire(is_output=False, alice_is_owner=False),  # 3
            GateWire(is_output=False, input_x_id=0, input_y_id=1, gate=gates["or"]),  # 4
            GateWire(is_output=False, input_x_id=4, input_y_id=2, gate=gates["and"]),  # 5
            GateWire(is_output=False, input_x_id=1, input_y_id=5, gate=gates["xor"]),  # 6
            GateWire(is_output=False, input_x_id=6, input_y_id=0, gate=gates["not-x"]),  # 7
            GateWire(is_output=False, input_x_id=2, input_y_id=7, gate=gates["or"]),  # 8
            GateWire(is_output=False, input_x_id=7, input_y_id=8, gate=gates["if"]),  # 9
            GateWire(is_output=False, input_x_id=4, input_y_id=9, gate=gates["and"]),  # 10
            GateWire(is_output=True, input_x_id=3, input_y_id=10, gate=gates["iff"]),  # 11
        ],
        "wide": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=True),  # 2
            InputWire(is_output=False, alice_is_owner=True),  # 3
            InputWire(is_output=False, alice_is_owner=True),  # 4
            InputWire(is_output=False, alice_is_owner=True),  # 5
            InputWire(is_output=False, alice_is_owner=False),  # 6
            InputWire(is_output=False, alice_is_owner=False),  # 7
            InputWire(is_output=False, alice_is_owner=False),  # 8
            InputWire(is_output=False, alice_is_owner=False),  # 9
            InputWire(is_output=False, alice_is_owner=False),  # 10
            InputWire(is_output=False, alice_is_owner=False),  # 11
            GateWire(is_output=False, input_x_id=0, input_y_id=6, gate=gates["or"]),  # 12
            GateWire(is_output=False, input_x_id=1, input_y_id=7, gate=gates["or"]),  # 13
            GateWire(is_output=False, input_x_id=2, input_y_id=8, gate=gates["or"]),  # 14
            GateWire(is_output=False, input_x_id=3, input_y_id=9, gate=gates["or"]),  # 15
            GateWire(is_output=False, input_x_id=4, input_y_id=10, gate=gates["or"]),  # 16
            GateWire(is_output=False, input_x_id=5, input_y_id=11, gate=gates["or"]),  # 17
            GateWire(is_output=True, input_x_id=12, input_y_id=15, gate=gates["and"]),  # 18
            GateWire(is_output=True, input_x_id=13, input_y_id=16, gate=gates["and"]),  # 19
            GateWire(is_output=True, input_x_id=14, input_y_id=17, gate=gates["and"]),  # 20
        ],
        "adder": [
            # Alice's input
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=True),  # 2
            InputWire(is_output=False, alice_is_owner=True),  # 3
            # Bob's input
            InputWire(is_output=False, alice_is_owner=False),  # 4
            InputWire(is_output=False, alice_is_owner=False),  # 5
            InputWire(is_output=False, alice_is_owner=False),  # 6
            InputWire(is_output=False, alice_is_owner=False),  # 7
            # Half adder 1
            GateWire(is_output=True, input_x_id=0, input_y_id=4, gate=gates["xor"]),  # 8
            GateWire(is_output=False, input_x_id=0, input_y_id=4, gate=gates["and"]),  # 9
            # Full adder 2
            GateWire(is_output=False, input_x_id=1, input_y_id=5, gate=gates["xor"]),  # 10
            GateWire(is_output=True, input_x_id=10, input_y_id=9, gate=gates["xor"]),  # 11
            GateWire(is_output=False, input_x_id=1, input_y_id=5, gate=gates["and"]),  # 12
            GateWire(is_output=False, input_x_id=9, input_y_id=10, gate=gates["and"]),  # 13
            GateWire(is_output=False, input_x_id=12, input_y_id=13, gate=gates["or"]),  # 14
            # Full adder 3
            GateWire(is_output=False, input_x_id=2, input_y_id=6, gate=gates["xor"]),  # 15
            GateWire(is_output=True, input_x_id=15, input_y_id=14, gate=gates["xor"]),  # 16
            GateWire(is_output=False, input_x_id=2, input_y_id=6, gate=gates["and"]),  # 17
            GateWire(is_output=False, input_x_id=14, input_y_id=15, gate=gates["and"]),  # 18
            GateWire(is_output=False, input_x_id=17, input_y_id=18, gate=gates["or"]),  # 19
            # Full adder 4
            GateWire(is_output=False, input_x_id=3, input_y_id=7, gate=gates["xor"]),  # 20
            GateWire(is_output=True, input_x_id=20, input_y_id=19, gate=gates["xor"]),  # 21
            GateWire(is_output=False, input_x_id=3, input_y_id=7, gate=gates["and"]),  # 22
            GateWire(is_output=False, input_x_id=19, input_y_id=20, gate=gates["and"]),  # 23
            GateWire(is_output=True, input_x_id=22, input_y_id=23, gate=gates["or"]),  # 24
        ],
        "xors": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=True),  # 2
            InputWire(is_output=False, alice_is_owner=False),  # 3
            InputWire(is_output=False, alice_is_owner=False),  # 4
            InputWire(is_output=False, alice_is_owner=False),  # 5
            GateWire(is_output=False, input_x_id=0, input_y_id=3, gate=gates["xor"]),  # 6
            GateWire(is_output=False, input_x_id=1, input_y_id=4, gate=gates["xor"]),  # 7
            GateWire(is_output=False, input_x_id=2, input_y_id=5, gate=gates["xor"]),  # 8
            GateWire(is_output=False, input_x_id=3, input_y_id=6, gate=gates["xor"]),  # 9
            GateWire(is_output=False, input_x_id=4, input_y_id=7, gate=gates["xor"]),  # 10
            GateWire(is_output=False, input_x_id=5, input_y_id=8, gate=gates["xor"]),  # 11
            GateWire(is_output=False, input_x_id=6, input_y_id=9, gate=gates["xor"]),  # 12
            GateWire(is_output=False, input_x_id=7, input_y_id=10, gate=gates["xor"]),  # 13
            GateWire(is_output=False, input_x_id=11, input_y_id=12, gate=gates["xor"]),  # 14
            GateWire(is_output=True, input_x_id=14, input_y_id=13, gate=gates["xor"]),  # 15
        ]
    }

    # ########################### testing testing ###########################
    # circuit = circuits["basic"]
    # wire4 = circuit[4]
    # print(wire4.gate(1, 1)) # lambda function lol
    # ########################### testing testing ###########################

    # alice = Alice(circuits["deep"], {0: True, 1: False}) # basic, deep
    # alice = Alice(circuits["wide"], {0: True, 1: False, 2: True, 3: False, 4: False, 5: False}) # wide
    # alice = Alice(circuits["adder"], {0: True, 1: False, 2: True, 3: False}) # adder
    alice = Alice(circuits["xors"], {0: True, 1: False, 2: True}) # xors
    # bob = Bob(alice, {2: False, 3: True}) # basic, deep 
    # bob = Bob(alice, {6: False, 7: True, 8: False, 9: False, 10: True, 11: False}) # wide
    # bob = Bob(alice, {4: False, 5: True, 6: False, 7: False}) # adder
    bob = Bob(alice, {3: False, 4: True, 5: False}) # xors


    print(run_garbled_circuit(alice, bob))

    print("COUNT_AES_Encrypt:", COUNT_AES_Encrypt)
    print("COUNT_AES_Decrypt:", COUNT_AES_Decrypt)
    print("COUNT_OT:", COUNT_OT)
    print("MESSAGES_SENT_GC:", MESSAGES_SENT_GC)


if __name__ == "__main__":

    main()
