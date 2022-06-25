import socket
from dns_package import DnsPackage
from dns_package_parser import DnsPackageParser
from time import time


class QuestionResolver:
    """
    Класс, у которого есть метод, который разрешает запрос
    и возвращает собранный ответ на запрос
    """

    def resolve_a(package: DnsPackage, cache: dict[bytes, DnsPackage]) -> bytes:
        """
        Метод, который рекурсивно разрешает запрос типа а
        и возвращает dns пакет с ответом
        :param package:
        :return: пакет, т.е. байты для клиента
        """
        HOST_ROOT = '198.41.0.4'
        if package.query in cache.keys():
            old_package = cache[package.query]
            time_now = time()
            if old_package.ttl + \
                    old_package.time_in_sec_from_epoch_start > time_now:
                old_package.transaction_id = package.transaction_id
                old_package.package = package.transaction_id + \
                                        old_package.package[2::]
                return old_package.package

        server_answer = QuestionResolver\
            .send_to_server_and_get_answer(package.package, HOST_ROOT)
        dns_package_answer = DnsPackageParser.parse_package(server_answer)
        answers_count = int.from_bytes(dns_package_answer.answer_rrs, "big")

        if answers_count > 0:
            return server_answer
        else:
            while True:
                # в Additional records надо найти запись у которой Type = \x00\x01
                # на host который там указан отправить запрос, если
                # в секции answers есть хоть один ответ, то вернуть этот пакет
                # если нет, то повторить всё снова
                additional_records = dns_package_answer.additional_records
                host = None
                for record in additional_records:
                    # запись типа А rdata содержит ip-адрес
                    if record.type == b'\x00\x01':
                        ip_s = []
                        for b in record.rdata:
                            ip_s.append(int.from_bytes([b], "big"))
                        ip_s = '.'.join(map(str, ip_s))
                        host = ip_s
                        break
                new_answer = QuestionResolver.send_to_server_and_get_answer(package.package, host)
                dns_package_answer = DnsPackageParser.parse_package(new_answer)
                answers_count = int.from_bytes(dns_package_answer.answer_rrs, "big")
                if answers_count > 0:
                    cache[dns_package_answer.query] = dns_package_answer
                    return new_answer

    def resolve_ns(package: DnsPackage, cache: dict[bytes, DnsPackage]) -> bytes:
        """
        Метод рекурсивно разрешает запрос типа ns
        :return: пакет dns с ответом в виде байтов
        """
        HOST_ROOT = '198.41.0.4'
        if package.query in cache.keys():
            old_package = cache[package.query]
            time_now = time()
            if old_package.ttl + \
                    old_package.time_in_sec_from_epoch_start > time_now:
                old_package.transaction_id = package.transaction_id
                old_package.package = package.transaction_id + \
                                        old_package.package[2::]
                return old_package.package

        server_answer = QuestionResolver \
            .send_to_server_and_get_answer(package.package, HOST_ROOT)
        dns_package_answer = DnsPackageParser.parse_package(server_answer)
        query_name = QuestionResolver.get_query_name(dns_package_answer.queries[0].name)
        authoritative_name = QuestionResolver.get_authoritative_name(
            dns_package_answer.package,
            dns_package_answer.authoritative_nameservers[0].name)
        if query_name.lower() == authoritative_name.lower():
            return dns_package_answer.package
        while True:
            # в Additional records надо найти запись у которой Type = \x00\x01
            # на host который там указан отправить запрос, если
            # если имена в запросе и Additional records совпадают, то
            # вернуть этот пакет
            # если нет, то повторить всё снова
            additional_records = dns_package_answer.additional_records
            host = None
            for record in additional_records:
                # запись типа А rdata содержит ip-адрес
                if record.type == b'\x00\x01':
                    ip_s = []
                    for b in record.rdata:
                        ip_s.append(int.from_bytes([b], "big"))
                    ip_s = '.'.join(map(str, ip_s))
                    host = ip_s
                    break
            new_answer = QuestionResolver.send_to_server_and_get_answer(package.package, host)
            dns_package_answer = DnsPackageParser.parse_package(new_answer)

            query_name = QuestionResolver.get_query_name(dns_package_answer.queries[0].name)
            authoritative_name = QuestionResolver.get_authoritative_name(
                dns_package_answer.package,
                dns_package_answer.authoritative_nameservers[0].name)
            if query_name.lower() == authoritative_name.lower():
                cache[dns_package_answer.query] = dns_package_answer
                return new_answer

    def get_query_name(query_name: bytearray) -> str:
        """
        :param package: пакет в котором лежит query
        :param query: запись с запросом
        :return: строку домен запроса
        """
        name_bytes = query_name
        name = []
        index = 0
        while name_bytes[index] != bytearray(b'\x00')[0]:
            number = name_bytes[index]
            index += 1
            for i in range(number):
                symbol = chr(name_bytes[index])
                name.append(symbol)
                index += 1
        return ''.join(name)

    def get_authoritative_name(package: bytes, query_name: bytearray):
        package = bytearray(package)
        name = []
        index = 0
        change_pos = False
        pos = None
        while query_name[index] != 0:
            if query_name[index] == 192:
                change_pos = True
                pos = query_name[index + 1]
                break
            number = query_name[index]
            index += 1
            for i in range(number):
                symbol = chr(query_name[index])
                name.append(symbol)
                index += 1

        if change_pos:
            while package[pos] != bytearray(b'\x00')[0]:
                number = package[pos]
                pos += 1
                for i in range(number):
                    symbol = chr(package[pos])
                    name.append(symbol)
                    pos += 1
        return ''.join(name)

    def send_to_server_and_get_answer(package: bytes, host: str) -> bytes:
        """
        Отправляет на хост host пакет package и возвращает
        пакет от сервера
        :param package:
        :param host:
        :return:
        """

        PORT = 53
        sock_to_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_to_dns.settimeout(1)
        sock_to_dns.sendto(package, (host, PORT))
        data = None
        try:
            data, _ = sock_to_dns.recvfrom(1024)
        except socket.error:
            print('error')
        return data
