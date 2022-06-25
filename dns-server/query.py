from dataclasses import dataclass


@dataclass
class Query:
    name: bytes
    type: bytes
    class_: bytes

    def __init__(self, name, type, class_):
        self.name = name
        self.type = type
        self.class_ = class_
