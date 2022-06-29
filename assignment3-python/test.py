
from random import SystemRandom
from typing import Dict, List

class TTP:
    """A trusted third party that can be trusted to generate Beaver triples."""

    def __init__(self, client_count: int, mod: int, rng: SystemRandom):
        """Initializes this [TTP], given the number of clients [client_count] participating in the protocol, the modulo
        [mod] to perform secret sharing under, and a source of randomness [rng]."""
        # raise Exception("Not implemented.")

        self.gate_map = {}

        # X = rng.randint(1, 10)
        # Y = rng.randint(1, 10)
        # Z = (X * Y) % mod # not sure about the mod

        self.mod = mod
        self.rng = rng
        self.client_count = client_count

    # def get_beaver_triple(self, gate_id: int, client_id: int) -> [int, int, int]:
    def get_beaver_triple(self, gate_id: int, client_id: int) -> List[int]:
        """Returns shares of the Beaver triple for multiplication gate [gate_id] for [client_id]. Make sure that clients
        requesting shares for the same [gate_id] actually get shares of the same Beaver triple."""
        # raise Exception("Not implemented.")

        if gate_id not in self.gate_map:
            X = self.rng.randint(1, 10)
            Y = self.rng.randint(1, 10)
            # Z = (X * Y) % self.mod # not sure about the mod
            Z = (X * Y) 

            # array of lists: [client_index][x,y,z]
            shares = [[] for _ in range(self.client_count)]

            # compute shares
            for i in range(self.client_count - 1):
                x, y, z = self.rng.randint(1, 10), self.rng.randint(1, 10), self.rng.randint(1, 10)
                X = (X - x) % self.mod
                Y = (Y - y) % self.mod
                Z = (Z - z) % self.mod
                shares[i].append(x)
                shares[i].append(y)
                shares[i].append(z)

            shares[self.client_count - 1].append(X)
            shares[self.client_count - 1].append(Y)
            shares[self.client_count - 1].append(Z)

            # save shares in map
            self.gate_map[gate_id] = shares


        return self.gate_map[gate_id][client_id]


def main():
    rng = SystemRandom()
    ttp = TTP(3, 13, rng)
    print(ttp.get_beaver_triple(1, 0))
    # print(ttp.get_beaver_triple(1, 0))
    # print(ttp.get_beaver_triple(1, 0))
    print(ttp.get_beaver_triple(1, 1))
    print(ttp.get_beaver_triple(1, 2))



if __name__ == "__main__":
    main()

