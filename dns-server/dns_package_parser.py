from dns_package import DnsPackage
from bitstring import BitArray
from query import Query
from answer import Answer


class DnsPackageParser:

    def parse_package(package: bytes) -> DnsPackage:

        ttl = None

        transaction_id = package[0:2:]

        flags = package[2:4:]
        flags_0 = BitArray(hex=str(flags[0])).bin
        flags_1 = BitArray(hex=str(flags[1])).bin

        questions_count = package[4:6:]
        answer_rrs = package[6:8:]
        authority_rrs = package[8:10:]
        additional_rrs = package[10:12:]

        queries = []
        answer_servers = []
        authoritative_nameservers = []
        additional_records = []

        index = 12
        questions_count_int = int.from_bytes(questions_count, "big")
        for i in range(questions_count_int):
            name = []
            while package[index] != 0:
                name.append(package[index])
                index += 1
            name.append(package[index])
            index += 1
            name = bytearray(name)
            type = package[index:index + 2:]
            index += 2
            class_ = package[index:index + 2:]
            query = Query(name, type, class_)
            queries.append(query)

        answer_servers_count_int = int.from_bytes(answer_rrs, "big")
        index += 2

        for i in range(answer_servers_count_int):
            name = []
            add = True
            while bytearray([package[index]]) != b'\x00':
                if bytearray([package[index]]) == b'\xc0':
                    name.append(package[index])
                    name.append(package[index+1])
                    index += 2
                    add = False
                    break
                name.append(package[index])
                index += 1
            if add:
                name.append(package[index])
                index += 1

            type = package[index:index + 2:]
            index += 2
            class_ = package[index:index + 2:]
            index += 2
            time_to_live = package[index:index + 4:]
            index += 4
            data_length = package[index:index + 2:]
            data_length_int = int.from_bytes(data_length, "big")
            index += 2
            rdata = []
            for _ in range(data_length_int):
                rdata.append(package[index])
                index += 1
            rdata = bytearray(rdata)
            answer = Answer(name, type, class_, time_to_live, data_length, rdata)
            answer_servers.append(answer)

        if answer_servers_count_int != 0:
            ttl = int.from_bytes(answer_servers[0].time_to_live, "big")

        authoritative_nameservers_count_int = \
            int.from_bytes(authority_rrs, "big")

        for i in range(authoritative_nameservers_count_int):
            name = []
            add = True
            while bytearray([package[index]]) != b'\x00':
                if bytearray([package[index]]) == b'\xc0':
                    name.append(package[index])
                    name.append(package[index + 1])
                    index += 2
                    add = False
                    break
                name.append(package[index])
                index += 1
            if add:
                name.append(package[index])
                index += 1

            type = package[index:index + 2:]
            index += 2
            class_ = package[index:index + 2:]
            index += 2
            time_to_live = package[index:index + 4:]
            index += 4
            data_length = package[index:index + 2:]
            data_length_int = int.from_bytes(data_length, "big")
            index += 2
            rdata = []
            try:
                for _ in range(data_length_int):
                    rdata.append(package[index])
                    index += 1
            except IndexError as ex:
                print('ERROR*******************************')

            answer = Answer(name, type, class_, time_to_live, data_length, rdata)
            authoritative_nameservers.append(answer)

        if authoritative_nameservers_count_int != 0 and ttl is None:
            ttl = int.from_bytes(authoritative_nameservers[0].time_to_live, 'big')

        additional_records_count_int = int.from_bytes(additional_rrs, "big")
        for i in range(additional_records_count_int):
            name = []
            add = True
            while bytearray([package[index]]) != b'\x00':
                if bytearray([package[index]]) == b'\xc0':
                    name.append(package[index])
                    name.append(package[index + 1])
                    index += 2
                    add = False
                    break
                name.append(package[index])
                index += 1
            if add:
                name.append(package[index])
                index += 1

            type = package[index:index + 2:]
            index += 2
            class_ = package[index:index + 2:]
            index += 2
            time_to_live = package[index:index + 4:]
            index += 4
            data_length = package[index:index + 2:]
            data_length_int = int.from_bytes(data_length, "big")
            index += 2
            rdata = []
            try:
                for _ in range(data_length_int):
                    rdata.append(package[index])
                    index += 1
            except IndexError:
                print(package)
                print(package[index])
            rdata = bytearray(rdata)
            answer = Answer(name, type, class_, time_to_live, data_length, rdata)
            additional_records.append(answer)

        query = queries[0]
        query_string = str(query.name + query.type + query.class_)

        return DnsPackage(transaction_id, flags, questions_count,
                 answer_rrs, authority_rrs, additional_rrs,
                 queries, answer_servers, authoritative_nameservers,
                 additional_records, package, ttl, query_string)
