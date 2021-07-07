import os
import sys
import crossplane
from icecream import ic
from datetime import datetime
from prettytable import PrettyTable
from Cryptodome.Hash import SHA as SHA1, SHA256, SHA384, SHA512
from pyasn1_modules import rfc2459
from pyasn1_modules import pem
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_modules.rfc2437 import sha1WithRSAEncryption
from pyasn1_modules.rfc2437 import RSAPublicKey
from pyasn1_modules.rfc2459 import id_ce_keyUsage as OID_EXT_KEY_USAGE, KeyUsage
from pyasn1_modules.rfc2459 import id_at_commonName as OID_COMMON_NAME

# Debug on or off hash out where appropriate
# ic.enable()
ic.disable()

payload = crossplane.parse('/etc/nginx/nginx.conf')

rsa_signing_algorithms = {
    sha1WithRSAEncryption: SHA1,  # defined in RFC 2437 (obsoleted by RFC 3447)
    ObjectIdentifier('1.2.840.113549.1.1.11'): SHA256,  # defined in RFC 3447
    ObjectIdentifier('1.2.840.113549.1.1.12'): SHA384,  # defined in RFC 3447
    ObjectIdentifier('1.2.840.113549.1.1.13'): SHA512}  # defined in RFC 3447


# A date has day 'd', month 'm' and year 'y'
class Date:
    def __init__(self, d, m, y):
        self.d = d
        self.m = m
        self.y = y

    # To store number of days in all months from
    # January to Dec.


monthDays = [31, 28, 31, 30, 31, 30,
             31, 31, 30, 31, 30, 31]


# This function counts number of leap years
# before the given date
def count_leap_years(d):
    years = d.y

    # Check if the current year needs to be considered
    # for the count of leap years or not
    if d.m <= 2:
        years -= 1

    # An year is a leap year if it is a multiple of 4,
    # multiple of 400 and not a multiple of 100.
    return int(years / 4 - years / 100 + years / 400)


# This function returns number of days between two
# given dates
def get_difference(dt1, dt2):
    # COUNT TOTAL NUMBER OF DAYS BEFORE FIRST DATE 'dt1'

    # initialize count using years and day
    n1 = dt1.y * 365 + dt1.d

    # Add days for months in given date
    for i in range(0, dt1.m - 1):
        n1 += monthDays[i]

    # Since every leap year is of 366 days,
    # Add a day for every leap year
    n1 += count_leap_years(dt1)

    # SIMILARLY, COUNT TOTAL NUMBER OF DAYS BEFORE 'dt2'

    n2 = dt2.y * 365 + dt2.d
    for i in range(0, dt2.m - 1):
        n2 += monthDays[i]
    n2 += count_leap_years(dt2)

    # return difference between two counts
    return n2 - n1


def from_bitstring_to_bytes(bs):
    i = int("".join(str(bit) for bit in bs), base=2)
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


def print_version(tbs_cert):
    version = tbs_cert['version']
    ic('Version: ' + version.prettyPrint())
    return version.prettyPrint()


def print_serial_number(tbs_cert):
    serial_number = tbs_cert['serialNumber']
    ic('Serial Number: ' + serial_number.prettyPrint())
    return serial_number.prettyPrint()


def print_issuer(tbs_cert):
    value = None
    issuer = tbs_cert['issuer'].getComponent()
    for relative_distinguished_name in issuer:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    ic('Issuer: ' + ds.getComponent().prettyPrint())
    return ds.getComponent().prettyPrint()


def print_validity(tbs_cert):
    validity = tbs_cert['validity']
    not_before = validity['notBefore'].getComponent()
    not_after = validity['notAfter'].getComponent()
    ic('Validity: ' + 'From: ' + str(not_before.asDateTime) + ' To: ' + str(not_after.asDateTime))
    now = datetime.now()
    dtd = int(datetime.strftime(now, '%d'))
    dtm = int(datetime.strftime(now, '%m'))
    dty = int(datetime.strftime(now, '%Y'))
    dd1 = Date(dtd, dtm, dty)
    cert_dd = int(datetime.strftime(not_after.asDateTime, '%d'))
    cert_dm = int(datetime.strftime(not_after.asDateTime, '%m'))
    cert_dy = int(datetime.strftime(not_after.asDateTime, '%Y'))
    dd2 = Date(cert_dd, cert_dm, cert_dy)
    date_diff = (get_difference(dd1, dd2))
    if date_diff <= 30:
        if date_diff < 0:
            ic("Certificate has expired")
            return str(date_diff)
        else:
            ic("Cert about to expire in " + str(date_diff) + " days")
            return str(date_diff)
    else:
        ic("Days to Expire: " + str(date_diff) + " days")
        return str(date_diff)


def get_subject(tbs_cert):
    value = None
    issuer = tbs_cert['subject'].getComponent()
    for relative_distinguished_name in issuer:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    return ds.getComponent()


def print_subject(tbs_cert):
    ic("Subject: " + get_subject(tbs_cert).prettyPrint())
    return "Subject: " + get_subject(tbs_cert).prettyPrint()


def get_public_key(tbs_cert):
    subject_public_key_info = tbs_cert['subjectPublicKeyInfo']
    return subject_public_key_info


def add_in_keys_dictionary(keys_dictionary, tbs_cert):
    if can_be_used_for_signing_certificates(tbs_cert) == 1:
        ic("CAN be used for signing certificates")
        subject_public_key = get_public_key(tbs_cert)
        subject = get_subject(tbs_cert)
        keys_dictionary.update({subject: subject_public_key})


def print_keys_dictionary(keys_dictionary):
    for key, value in keys_dictionary.items():
        print(key, value)


def find_key_usage(extensions):
    return next(e['extnValue'] for e in extensions if e['extnID'] == OID_EXT_KEY_USAGE)


def can_be_used_for_signing_certificates(tbs_cert):
    extensions = tbs_cert['extensions']
    ku_ext = find_key_usage(extensions)
    octet_stream, rest = der_decoder.decode(ku_ext)
    ku, rest = der_decoder.decode(octet_stream, asn1Spec=KeyUsage())
    key_cert_bit = KeyUsage.namedValues.getValue('keyCertSign')
    try:
        return ku[key_cert_bit]
    except Exception as e:
        ic("CAN'T be used for signing certificates")
        return False


def get_exp_and_mod(subject_pk):
    algorithm_oid = subject_pk['algorithm']['algorithm']
    # algorithm_oid == OID_RSA_ENCRYPTION
    pk = from_bitstring_to_bytes(subject_pk['subjectPublicKey'])
    rsa_pk, rest = der_decoder.decode(pk, asn1Spec=RSAPublicKey())
    return rsa_pk['publicExponent'], rsa_pk['modulus']


def signature_check(cert, keys_dictionary):
    tbs_cert = cert['tbsCertificate']
    print('Verifying certificate for ' + get_subject(tbs_cert))
    if is_self_signed(tbs_cert):
        ic('Self-Signed Certificate')
        return
    signature_algo = cert['signatureAlgorithm']
    algo_oid = signature_algo['algorithm']
    sv = cert['signatureValue']
    signature_value = int("".join(str(bit) for bit in sv), base=2)
    rsa_signing_algorithm = rsa_signing_algorithms[algo_oid].new()
    rsa_signing_algorithm.update(der_encoder.encode(tbs_cert))
    digest_tbs_cert = rsa_signing_algorithm.hexdigest()
    issuer_name = get_issuer(tbs_cert)
    issuer_public_key = keys_dictionary.get(issuer_name)
    issuer_exponent, issuer_modulus = get_exp_and_mod(issuer_public_key)
    signed_value = pow(signature_value, int(issuer_exponent), int(issuer_modulus))
    sv = hex(signed_value)
    ic("Signed by " + issuer_name if digest_tbs_cert in sv else "WARNING")


def get_issuer(tbs_cert):
    value = None
    issuer = tbs_cert['issuer'].getComponent()
    for relative_distinguished_name in issuer:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    return "Issuer : " + ds.getComponent().prettyPrint()


def is_self_signed(tbs_cert):
    subject = get_subject(tbs_cert)
    issuer = get_issuer(tbs_cert)
    if subject == issuer:
        return True
    return False


def print_summary(tbs_cert):
    version = print_version(tbs_cert)
    serial = print_serial_number(tbs_cert)
    issuer = print_issuer(tbs_cert)
    subject = print_subject(tbs_cert)
    validity = print_validity(tbs_cert)
    return version, serial, issuer, subject, validity


def play():
    file_name = ""
    server_name = ""
    ssl_certificate = ""
    # Create Table Arrays to store the results
    e = PrettyTable()
    e.align = "r"
    e.field_names = ["Config File: ", " Server: ", "SSL CERT FILE", "version", "serial", "issuer", "subject",
                     "validity"]
    d = PrettyTable()
    d.align = "r"
    d.field_names = ["Config File: ", " Server: ", "SSL CERT FILE", "version", "serial", "issuer", "subject",
                     "validity"]
    x = PrettyTable()
    x.align = "r"
    x.field_names = ["Config File: ", " Server: ", "SSL CERT FILE", "version", "serial", "issuer", "subject",
                     "validity"]

    # payload = crossplane.parse("nginx.conf")
    # This will return a dictionary called payload
    # status = this returns the value "ok" if the parser was successful in reading  the configuration file.
    # errors = any errors found in the file
    # config = configuration items
    # __len__() = dictionary length at the top level this is a static value of 3
    # check that the parse has worked and exit script if it has not.
    import_status = payload['status']
    if import_status != "ok":
        print("Import of config file nginx.conf has failed.")
        exit(1)
    # The configuration dictionary has the following format
    # file = the config file name
    # status = this returns the value "ok" if the parser was successful in reading  the configuration file.
    # errors = any errors found in the file
    # parsed = this is a dictionary of the items which ware parsed from an individual config file.
    # __len__() = dictionary length at this level

    # How many items are there in the dictionary config as this holds all the relevant information we need
    # starts from [0] to [n]
    config_len = (payload['config'].__len__())
    for cl in range(config_len):
        # The config file name in which you are going to find the server name
        file_name = (payload['config'][cl]['file'])
        ic("1. Config File:" + file_name)
        # '/etc/nginx/conf.d\\201-swift-emea02.conf'
        # parsed is a dictionary of all the config items which are in the config file.
        parsed_config_len = (payload['config'][cl]['parsed'].__len__())
        # print(parsed_config_len)
        # the number of items which contained within the parsed dictionary
        for pcl in range(parsed_config_len):
            # Each item is a dictionary with the following format.
            # directive: <tag name>
            # line:  <line number  in the config file>
            # args:  < any arguments for this tag name>
            # block: < config items for this tag name> and this is dictionary
            # __len__()
            # find the server name in the parsed block by searching  for the server_name tag name
            tag_name = (payload['config'][cl]['parsed'][pcl]['directive'])  # 'server'
            if tag_name == "server":
                tag_name_len = (payload['config'][cl]['parsed'][pcl]['block'].__len__())

                for tnl in range(tag_name_len):
                    # Search the server_name block for the actual server name.
                    # 'server_name'
                    tag_server_name = (payload['config'][cl]['parsed'][pcl]['block'][tnl]['directive'])
                    tag_ssl_certificate = (payload['config'][cl]['parsed'][pcl]['block'][tnl]['directive'])
                    # 'ssl_certificate'
                    if tag_server_name == 'server_name':
                        tag_server_name_len = (payload['config'][cl]['parsed'][pcl]['block'][tnl]['args'].__len__())
                        for snl in range(tag_server_name_len):
                            server_name = (payload['config'][cl]['parsed'][pcl]['block'][tnl]['args'][snl])
                            ic("2. Config File: " + file_name + " Server: " + server_name)
                            # 'api-emea02.trakm8.net'
                    if tag_ssl_certificate == 'ssl_certificate':
                        ssl_certificate = (payload['config'][cl]['parsed'][pcl]['block'][tnl]['args'][0])
                        # 'ssl_certificate'
                        ic("3. Config File: " + file_name + " Server: " + server_name + " SSL Cert: " + ssl_certificate)
                        certificates_list = list()
                        ic('Checking File:' + ssl_certificate)
                        with open(ssl_certificate) as f:
                            binary_data = pem.readPemFromFile(f)
                            cert, rest = der_decoder.decode(binary_data, asn1Spec=rfc2459.Certificate())
                            tbs_cert = cert['tbsCertificate']
                            certificates_list.append(cert)
                            # summary = print_summary(tbs_cert)
                            version = print_version(tbs_cert)
                            serial = print_serial_number(tbs_cert)
                            issuer = print_issuer(tbs_cert)
                            subject = print_subject(tbs_cert)
                            validity = print_validity(tbs_cert)
                            # summary = version, serial, issuer, subject, validity

                            if int(validity) <= 0:
                                e.add_row(
                                    [file_name, server_name, ssl_certificate, version, serial, issuer, subject,
                                     validity])

                            if int(validity) <= 30 >= 1:
                                d.add_row(
                                    [file_name, server_name, ssl_certificate, version, serial, issuer, subject,
                                     int(validity)])
                            else:
                                x.add_row(
                                    [file_name, server_name, ssl_certificate, version, serial, issuer, subject,
                                     int(validity)])

    d.align = "l"
    d.reversesort = True
    d.sortby = "validity"

    e.align = "l"
    e.reversesort = True
    e.sortby = "validity"

    x.align = "l"
    # x.reversesort = True
    x.sortby = "validity"
    # Debug only
    ic(d)
    ic(e)
    ic(x)

    print("Expired Certs")
    print(e.get_string(fields=["Config File: ", " Server: ", "SSL CERT FILE", "issuer", "subject", "validity"]))
    print()
    print("30 Days Left Certs")
    print(e.get_string(fields=["Config File: ", " Server: ", "SSL CERT FILE", "issuer", "subject", "validity"]))
    print()
    print("Valid Certs")
    print(x.get_string(fields=["Config File: ", " Server: ", "SSL CERT FILE", "issuer", "subject", "validity"]))


if __name__ == '__main__':
    play()
